package outbound

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// encryptDescEcb builds a macc server descriptor the way the reference core
// expects: AES-256-ECB(SHA256(keyInput||protocolParam||salt)) over "host:port",
// hex-encoded, wrapped as "prefix-<hex>.<domain>".
func encryptDescEcb(plain, keyInput, protocolParam string) string {
	key := deriveMaccKey(keyInput, protocolParam)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return hex.EncodeToString(out)
}

func TestParseMaccServerDotVariant(t *testing.T) {
	C.MaccSalt = "unit-test-salt"
	pp := "71461:aaaa-bbbb-cccc"
	domain := "sev.cloudfront.net"
	enc := encryptDescEcb("203.0.113.7:8443", domain, pp)
	host, port, dom, err := parseMaccServer("doedge-"+enc+"."+domain, pp)
	if err != nil {
		t.Fatal(err)
	}
	if host != "203.0.113.7" || port != 8443 || dom != domain {
		t.Fatalf("got %s %d %s", host, port, dom)
	}
}

func TestParseMaccServerThreePart(t *testing.T) {
	C.MaccSalt = "unit-test-salt"
	pp := "71461:aaaa-bbbb"
	enc := encryptDescEcb("198.51.100.9:443", "example.com", pp)
	host, port, dom, err := parseMaccServer("pre-"+enc+"-example.com", pp)
	if err != nil {
		t.Fatal(err)
	}
	if host != "198.51.100.9" || port != 443 || dom != "example.com" {
		t.Fatalf("got %s %d %s", host, port, dom)
	}
}

func TestExtractMaccDomain(t *testing.T) {
	cases := map[string]string{
		"sev.cloudfront.net": "cloudfront.net",
		"example.com":        "com",
		"nodot":              "nodot",
		".leading":           ".leading",
	}
	for in, want := range cases {
		if got := extractMaccDomain(in); got != want {
			t.Fatalf("extractMaccDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMaccSaltGuard(t *testing.T) {
	old := C.MaccSalt
	C.MaccSalt = ""
	defer func() { C.MaccSalt = old }()
	if _, _, _, err := parseMaccServer("a-b-c", "x"); err == nil || !strings.Contains(err.Error(), "MaccSalt") {
		t.Fatalf("salt guard: %v", err)
	}
}

func TestMaccConstructor(t *testing.T) {
	C.MaccSalt = "unit-test-salt"
	pp := "71461:aaaa-bbbb"
	enc := encryptDescEcb("127.0.0.1:1080", "d.example.com", pp)
	m, err := NewMacc(MaccOption{
		Name:          "macc-test",
		Server:        "aa-" + enc + ".d.example.com",
		Password:      "cipher-pw",
		Cipher:        "rc4-md5",
		Obfs:          "http_simple",
		ObfsParam:     "ajax.microsoft.com",
		Protocol:      "auth_aes128_md5",
		ProtocolParam: pp,
		UDP:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != C.Macc {
		t.Fatal("type")
	}
	if m.Addr() != "127.0.0.1:1080" {
		t.Fatalf("addr = %s", m.Addr())
	}
	if !m.SupportUDP() {
		t.Fatal("udp")
	}
}
