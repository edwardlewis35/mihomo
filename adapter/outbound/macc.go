package outbound

// macc.go — Mielink/FlClash "macc" outbound protocol, reconstructed from
// Ghidra decompilation of the reference core (Mielink MaccCore / FlClashCore)
// plus black-box verification against a live subscription descriptor.
//
// Full evidence chain (Ghidra pseudocode: cmynetwork-analysis/ghidra_macc_pseudo.c):
//
//	parseMaccServer(server, protocolParam):
//	  - 3-part regex ^([^-]+)-([^-]+)-(.+)$  -> enc=m[2], domain=m[3]
//	  - else 2-part: splitN(server,"-",2) -> [prefix, rest];
//	                 dot = IndexByte(rest,'.'); enc=rest[:dot], domain=rest[dot+1:]
//	  - decryptMaccPayload(enc, domain, protocolParam) -> "host:port"
//	  - split ':' -> host, Atoi(port)
//
//	decryptMaccPayload(enc, X, Y):
//	  - all-hex & even length -> decryptMaccHex(enc, X, Y)
//	  - else base64: key=SHA256(X||Y||salt); AES-256-CBC(iv=dec[:16], ct=dec[16:]); PKCS7
//
//	decryptMaccHex(enc, X, Y):
//	  - hex decode; len!=0 && len%16==0
//	  - candidates = dedup([extractMaccDomain(X), X])
//	  - per candidate: key=SHA256(cand||Y||salt); AES-256-**ECB** (per-16B block.Decrypt,
//	    no chaining, no IV); PKCS7 unpad; first success wins
//
//	extractMaccDomain(s): index of first '.' > 0 -> s[i+1:], else s
//
//	deriveMaccKey(a,b): SHA256(a||b||MaccSalt), 32 bytes (AES-256)
//
//	NewMacc: parseMaccServer(option.Server, option.ProtocolParam); the password is
//	NOT part of descriptor decryption (it feeds the SSR cipher stack below).
//
// Verified: subscription descriptor
//   doedge-7f92…49f8.sev.cloudfront.net -> "gtm-6wr2p27i308-am.gocmydns.com:769"
//   (all 10 macc nodes of the live gotocmy subscription decrypt correctly)

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/ssr/obfs"
	"github.com/metacubex/mihomo/transport/ssr/protocol"
)

type Macc struct {
	*Base
	option   *MaccOption
	cipher   core.Cipher
	obfs     obfs.Obfs
	protocol protocol.Protocol
	domain   string
}

type MaccOption struct {
	BasicOption
	Name          string `proxy:"name"`
	Server        string `proxy:"server,omitempty"`  // prefix-<enc>.<domain> descriptor
	Address       string `proxy:"address,omitempty"` // legacy alias of Server
	Port          int    `proxy:"port,omitempty"`    // ignored: real port comes from descriptor
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Obfs          string `proxy:"obfs,omitempty"`
	ObfsParam     string `proxy:"obfs-param,omitempty"`
	ObfsPassword  string `proxy:"obfs-password,omitempty"`
	Protocol      string `proxy:"protocol,omitempty"`
	ProtocolParam string `proxy:"protocol-param,omitempty"`
	UDP           bool   `proxy:"udp,omitempty"`
	L3            bool   `proxy:"l3,omitempty"`
}

var maccServerRE = regexp.MustCompile(`^([^-]+)-([^-]+)-(.+)$`)

// StreamConnContext implements C.ProxyAdapter.
func (ss *Macc) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	c = ss.obfs.StreamConn(c)
	c = ss.cipher.StreamConn(c)
	var (
		iv []byte
	)
	switch conn := c.(type) {
	case *shadowstream.Conn:
		iv, err = conn.ObtainWriteIV()
		if err != nil {
			return nil, err
		}
	case *shadowaead.Conn:
		return nil, fmt.Errorf("invalid connection type")
	}
	c = ss.protocol.StreamConn(c, iv)
	_, err = c.Write(serializesSocksAddr(metadata))
	return c, err
}

// DialContext implements C.ProxyAdapter
func (ss *Macc) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := ss.dialer.DialContext(ctx, "tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConnContext(ctx, c, metadata)
	return NewConn(c, ss), err
}

// ListenPacketContext implements C.ProxyAdapter
func (ss *Macc) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := ss.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	addr, err := resolveUDPAddr(ctx, "udp", ss.addr, ss.prefer)
	if err != nil {
		return nil, err
	}

	pc, err := ss.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, err
	}

	epc := ss.cipher.PacketConn(N.NewEnhancePacketConn(pc))
	epc = ss.protocol.PacketConn(epc)
	return NewPacketConn(&maccPacketConn{EnhancePacketConn: epc, rAddr: addr}, ss), nil
}

// IsL3Protocol implements C.ProxyAdapter
func (ss *Macc) IsL3Protocol(metadata *C.Metadata) bool {
	return ss.option.L3
}

// ProxyInfo implements C.ProxyAdapter
func (ss *Macc) ProxyInfo() C.ProxyInfo {
	info := ss.Base.ProxyInfo()
	info.DialerProxy = ss.option.DialerProxy
	return info
}

func NewMacc(option MaccOption) (*Macc, error) {
	if C.MaccSalt == "" {
		return nil, errors.New(`MaccSalt not set, please set MIHOMO_MACC_SALT at build time (recommended) or compile with -ldflags '-X "github.com/metacubex/mihomo/constant.MaccSalt=your-salt"'`)
	}

	descriptor := option.Server
	if descriptor == "" {
		descriptor = option.Address
	}
	// descriptor decryption uses protocol-param as the second key input
	host, port, domain, err := parseMaccServer(descriptor, option.ProtocolParam)
	if err != nil {
		return nil, fmt.Errorf("parse macc server error: %w", err)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// ss cipher stack
	cipherName := option.Cipher
	password := option.Password
	coreCiph, err := core.PickCipher(cipherName, nil, password)
	if err != nil {
		return nil, fmt.Errorf("macc %s cipher: %s initialize error: %w", addr, cipherName, err)
	}
	var (
		ivSize int
		key    []byte
	)
	if cipherName == "dummy" || cipherName == "none" {
		if cipherName == "none" {
			cipherName = "dummy"
			coreCiph, err = core.PickCipher(cipherName, nil, password)
			if err != nil {
				return nil, fmt.Errorf("macc %s cipher: %s initialize error: %w", addr, cipherName, err)
			}
		}
		ivSize = 0
		key = core.Kdf(option.Password, 16)
	} else {
		ciph, ok := coreCiph.(*core.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("%s is not none or a supported stream cipher in ssr", cipherName)
		}
		ivSize = ciph.IVSize()
		key = ciph.Key
	}

	obfsName := option.Obfs
	if obfsName == "" {
		obfsName = "plain"
	}
	ob, obfsOverhead, err := obfs.PickObfs(obfsName, &obfs.Base{
		Host:   host,
		Port:   port,
		Key:    key,
		IVSize: ivSize,
		Param:  option.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("macc %s initialize obfs error: %w", addr, err)
	}

	protoName := option.Protocol
	if protoName == "" {
		protoName = "origin"
	}
	proto, err := protocol.PickProtocol(protoName, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    option.ProtocolParam,
	})
	if err != nil {
		return nil, fmt.Errorf("macc %s initialize protocol error: %w", addr, err)
	}

	outbound := &Macc{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Macc,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:   &option,
		cipher:   coreCiph,
		obfs:     ob,
		protocol: proto,
		domain:   domain,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

type maccPacketConn struct {
	N.EnhancePacketConn
	rAddr net.Addr
}

func (mpc *maccPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	packet = packet[3:] // drop RSV/FRAG like ssr
	_, err = mpc.EnhancePacketConn.WriteTo(packet, mpc.rAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (mpc *maccPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := mpc.EnhancePacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}
	addr := socks5.SplitAddr(b[:n])
	if addr == nil {
		return 0, nil, errors.New("parse addr error")
	}
	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse addr error")
	}
	copy(b, b[len(addr):])
	return n - len(addr), udpAddr, e
}

// ---- descriptor crypto (verified against live subscription) -------------------

// deriveMaccKey = SHA256(arg1 || arg2 || MaccSalt), 32 bytes.
func deriveMaccKey(arg1, arg2 string) []byte {
	h := sha256.New()
	h.Write([]byte(arg1))
	h.Write([]byte(arg2))
	h.Write([]byte(C.MaccSalt))
	return h.Sum(nil)
}

// decryptMaccPayload mirrors decryptMaccPayload@0x11423c0.
func decryptMaccPayload(encoded, x, y string) (string, error) {
	if C.MaccSalt == "" {
		return "", errors.New("MaccSalt not set")
	}
	if len(encoded)%2 == 0 && isHexString(encoded) {
		return decryptMaccHex(encoded, x, y)
	}
	key := deriveMaccKey(x, y)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %w", err)
	}
	if len(raw) < 2*aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	ct := raw[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext length invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher error: %w", err)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, raw[:aes.BlockSize]).CryptBlocks(out, ct)
	plain, err := pkcs7Unpad(out, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("unpad error: %w", err)
	}
	return string(plain), nil
}

// decryptMaccHex mirrors decryptMaccHex@0x1142860: AES-256-ECB over 16-byte
// blocks (no chaining, no IV), candidate keys from [domain-suffix, domain].
func decryptMaccHex(encoded, x, y string) (string, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("hex decode error: %w", err)
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext length invalid")
	}
	cands := []string{extractMaccDomain(x)}
	if cands[0] != x {
		cands = append(cands, x)
	}
	var lastErr error
	for _, c := range cands {
		key := deriveMaccKey(c, y)
		block, err := aes.NewCipher(key)
		if err != nil {
			lastErr = fmt.Errorf("create cipher error: %w", err)
			continue
		}
		out := make([]byte, len(raw))
		for i := 0; i < len(raw); i += aes.BlockSize {
			block.Decrypt(out[i:i+aes.BlockSize], raw[i:i+aes.BlockSize])
		}
		plain, err := pkcs7Unpad(out, aes.BlockSize)
		if err == nil {
			return string(plain), nil
		}
		lastErr = fmt.Errorf("unpad error: %w", err)
	}
	if lastErr == nil {
		lastErr = errors.New("decrypt failed")
	}
	return "", lastErr
}

// pkcs7Unpad mirrors pkcs7Unpad@0x1142d60.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding: empty data")
	}
	n := int(data[len(data)-1])
	if n <= 0 || n > blockSize || n > len(data) {
		return nil, errors.New("invalid padding bytes")
	}
	for _, b := range data[len(data)-n:] {
		if b != byte(n) {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-n], nil
}

// parseMaccServer mirrors parseMaccServer@0x1142ec0 (returns host, port, domain).
func parseMaccServer(address, secondary string) (host string, port int, domain string, err error) {
	if C.MaccSalt == "" {
		return "", 0, "", errors.New("MaccSalt not set")
	}
	var enc, dom string
	if m := maccServerRE.FindStringSubmatch(address); m != nil {
		enc, dom = m[2], m[3]
	} else {
		parts := strings.SplitN(address, "-", 2)
		if len(parts) != 2 {
			return "", 0, "", fmt.Errorf("invalid macc server format: %s (expected format: prefix-encrypted[-|.]domain)", address)
		}
		rest := parts[1]
		i := strings.IndexByte(rest, '.')
		if i < 1 {
			return "", 0, "", fmt.Errorf("invalid macc server format: %s (expected format: prefix-encrypted.domain)", address)
		}
		enc, dom = rest[:i], rest[i+1:]
	}
	plain, err := decryptMaccPayload(enc, dom, secondary)
	if err != nil {
		return "", 0, "", fmt.Errorf("decrypt server error: %w", err)
	}
	hp := strings.Split(plain, ":")
	if len(hp) != 2 || hp[0] == "" || hp[1] == "" {
		return "", 0, "", fmt.Errorf("invalid decrypted server format: %s (expected host:port)", plain)
	}
	p, err := strconv.Atoi(hp[1])
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid port: %s", hp[1])
	}
	return hp[0], p, dom, nil
}

// extractMaccDomain returns the suffix after the first '.' (whole string if none/leading).
func extractMaccDomain(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[i+1:]
	}
	return s
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
