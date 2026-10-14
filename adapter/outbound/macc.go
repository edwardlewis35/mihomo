package outbound

// macc.go — reverse-engineered reconstruction of the Mielink/FlClash "macc"
// outbound protocol, injected into mihomo (Meta branch).
//
// Evidence map (see workspace-rea/flc-macc-analysis/macc-extract/):
//
//	[EVIDENCED] server descriptor format  prefix-<hex|b64 ciphertext>-<domain>
//	[EVIDENCED] descriptor key derivation SHA-256(arg1 || arg2 || C.MaccSalt)
//	[EVIDENCED] descriptor cipher         AES-256-CBC + PKCS7 (len%16 checks,
//	                                      pkcs7Unpad symbol, error strings)
//	[EVIDENCED] stream stack              ss core.PickCipher+Kdf, ssr obfs,
//	                                      ssr protocol (constructor call order +
//	                                      "macc %s cipher/obfs/protocol
//	                                      initialize error" strings)
//	[EVIDENCED] stream header             shadowstream ObtainWriteIV +
//	                                      serializesSocksAddr written to conn
//	[EVIDENCED] UDP                       socks5.EncodeUDPPacket inside the
//	                                      encrypted conn (maccPacketConn.WriteTo)
//	[EVIDENCED] capabilities              SupportUDP, SupportUOT, IsL3Protocol
//
//	[EVIDENCED] deriveMaccKey inputs: candidate key strings =
//	              [extractMaccDomain(secondary), secondary], arg2 = secondary
//	              (option field @+0xd0, inferred Password) [INFERRED mapping]
//	[EVIDENCED] CBC IV policy: hand-rolled CBC decrypt loop (per-16B Decrypt +
//	              xor chain, len>=32 guard) => first 16 bytes are the IV
//	[EVIDENCED] UDP framing: WriteTo trims the 3-byte RSV/FRAG prefix
//	              (lea rdi,[rcx-0x3]; lea rcx,[rbx-0x3] @MaccCore 0x1143fca)
//	[UNKNOWN]   `prefix` field semantics (kept verbatim, unused)
//	[UNKNOWN]   whether maccPacketConn strips the 3-byte socks5 RSV/FRAG header
//	              like ssr does (kept full packet here; toggle with trim flag)

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
	domain   string // camouflage domain extracted from descriptor
}

type MaccOption struct {
	BasicOption
	Name          string `proxy:"name"`
	Address       string `proxy:"address"` // prefix-<encrypted>-<domain>
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Obfs          string `proxy:"obfs,omitempty"`
	ObfsParam     string `proxy:"obfs-param,omitempty"`
	ObfsPassword  string `proxy:"obfs-password,omitempty"`
	Protocol      string `proxy:"protocol,omitempty"`
	ProtocolParam string `proxy:"protocol-param,omitempty"`
	UDP           bool   `proxy:"udp,omitempty"`
	L3            bool   `proxy:"l3,omitempty"` // [UNKNOWN] flag name inferred from IsL3Protocol
}

// maccServerRE is taken verbatim from the target binary rodata:
// "^([^-]+)-([^-]+)-(.+)$"  [EVIDENCED]
var maccServerRE = regexp.MustCompile(`^([^-]+)-([^-]+)-(.+)$`)

// StreamConnContext implements C.ProxyAdapter.
// Sequence mirrors (*Macc).StreamConnContext in the original binary [EVIDENCED]:
// obfs layer -> ss stream cipher -> ObtainWriteIV -> protocol layer -> socks addr.
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

// IsL3Protocol implements C.ProxyAdapter.
// Original binary checks a non-nil optional field at Macc+0x20 [EVIDENCED];
// here it is driven by the explicit `l3` config flag [UNKNOWN semantics].
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

	// descriptor: prefix-<encrypted>-<domain> -> real host:port  [EVIDENCED]
	server, port, domain, err := parseMaccServer(option.Address, option.Password)
	if err != nil {
		return nil, fmt.Errorf("parse macc server error: %w", err)
	}
	addr := net.JoinHostPort(server, port)

	// ss cipher stack  [EVIDENCED: core.PickCipher + core.Kdf call sites]
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

	// ssr obfs layer  [EVIDENCED: obfs.PickObfs call site + error string]
	obfsName := option.Obfs
	if obfsName == "" {
		obfsName = "plain"
	}
	ob, obfsOverhead, err := obfs.PickObfs(obfsName, &obfs.Base{
		Host:   server,
		Port:   mustPort(port),
		Key:    key,
		IVSize: ivSize,
		Param:  option.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("macc %s initialize obfs error: %w", addr, err)
	}

	// ssr protocol layer  [EVIDENCED: protocol.PickProtocol call site]
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

// WriteTo mirrors maccPacketConn.WriteTo@0x140d11200:
// socks5.ParseAddrToSocksAddr + socks5.EncodeUDPPacket [EVIDENCED].
// The 3-byte RSV/FRAG prefix IS trimmed, exactly like ssr — confirmed in the
// MaccCore disassembly (bounds check cmp rbx,0x3 + pointer/len -3 adjust).
func (mpc *maccPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	if trimRSV {
		packet = packet[3:]
	}
	_, err = mpc.EnhancePacketConn.WriteTo(packet, mpc.rAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

var trimRSV = true // [EVIDENCED] original trims RSV/FRAG: lea rdi,[rcx-0x3]; lea rcx,[rbx-0x3]

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

// ---- descriptor crypto -------------------------------------------------------

// deriveMaccKey mirrors deriveMaccKey@0x140d105e0:
// SHA-256(arg1 || arg2 || MaccSalt), 32-byte output. [EVIDENCED structure]
// arg1 = candidate key string (decoded ciphertext bytes or descriptor segment),
// arg2 = secondary option field (inferred: password). [EVIDENCED: candidate
// loop @MaccCore 0x1142a65..0x1142ab5 walks a deduped []string of candidates]
func deriveMaccKey(arg1, arg2 string) []byte {
	h := sha256.New()
	h.Write([]byte(arg1))
	h.Write([]byte(arg2))
	h.Write([]byte(C.MaccSalt))
	return h.Sum(nil)
}

// decryptMaccPayload mirrors decryptMaccPayload@0x140d0f4c0 plus the
// multi-candidate key loop of decryptMaccHex (@0x1142860, register-traced):
//  1. salt-empty guard                                        [EVIDENCED]
//  2. even length && all hex digits -> hex path, else base64
//     (bt len,0 + hexdigit scan @0x11426e6)                   [EVIDENCED]
//  3. candidates = [extractMaccDomain(secondary), secondary],
//     deduped via memequal (@0x1142980; extractMaccDomain call
//     @0x1142965 -> 0x11427c0)                                [EVIDENCED]
//  4. per candidate: deriveMaccKey(candidate, secondary) ->
//     AES-256-CBC(prefix IV) -> PKCS7; first success wins
//     (loop @0x1142a65, derive call @0x1142ab5)               [EVIDENCED]
//
// secondary = parseMaccServer arg2 = option field @+0xd0,
// inferred Password                                           [INFERRED]
func decryptMaccPayload(encoded, secondary string) (string, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(encoded)%2 != 0 || !isHexString(encoded) {
		raw, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("base64 decode error: %w", err)
		}
	}
	domain := extractMaccDomain(secondary)
	cands := []string{domain}
	if domain != secondary {
		cands = append(cands, secondary)
	}
	var lastErr error
	for _, c := range cands {
		plain, err := decryptMaccCBC(raw, c, secondary)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return "", lastErr
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

func decryptMaccCBC(raw []byte, candidate, secondary string) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("ciphertext too short")
	}
	if len(raw)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext length invalid")
	}
	if len(raw) < 2*aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	key := deriveMaccKey(candidate, secondary)
	// IV = first 16 bytes [EVIDENCED: hand-rolled CBC loop, 2-block minimum].
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher error: %w", err)
	}
	iv, ct := raw[:aes.BlockSize], raw[aes.BlockSize:]
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	plain, err := pkcs7Unpad(out, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("unpad error: %w", err)
	}
	return string(plain), nil
}

// pkcs7Unpad mirrors pkcs7Unpad@0x140d0ff60. [EVIDENCED error strings]
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

// parseMaccServer mirrors parseMaccServer@0x140d100a0. [EVIDENCED]
func parseMaccServer(address, password string) (host, port, domain string, err error) {
	m := maccServerRE.FindStringSubmatch(address)
	if m == nil {
		return "", "", "", fmt.Errorf("invalid macc server format: %s (expected format: prefix-encrypted[-|.]domain)", address)
	}
	plain, err := decryptMaccPayload(m[2], password)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypt server error: %w", err)
	}
	host, port, ok := strings.Cut(strings.TrimSpace(plain), ":")
	if !ok || host == "" || port == "" {
		return "", "", "", fmt.Errorf("invalid decrypted server format: %s (expected host:port)", plain)
	}
	return host, port, m[3], nil
}

// extractMaccDomain mirrors extractMaccDomain@0x11427c0 (MaccCore):
// strings.Index(s, ".") -> return suffix AFTER first dot; whole string when
// no dot or dot at position 0. Separator byte 0x2e @0x19eee28, len 1.
// [EVIDENCED: lea rcx,[rip]#0x19eee28; edi=1; Index; rdx=rax+1; ptr+=rax+1]
func extractMaccDomain(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[i+1:]
	}
	return s
}

func mustPort(p string) int {
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
