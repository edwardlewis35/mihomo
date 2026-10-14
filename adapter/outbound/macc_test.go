package outbound

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func testEncryptDescriptor(plain, password string, useB64 bool) string {
	key := deriveMaccKey(password, "")
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	block, _ := aes.NewCipher(key)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(iv)+len(data))
	copy(out, iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[len(iv):], data)
	if useB64 {
		return base64.StdEncoding.EncodeToString(out)
	}
	return hex.EncodeToString(out)
}

func TestParseMaccServer(t *testing.T) {
	C.MaccSalt = "test-salt"
	enc := testEncryptDescriptor("203.0.113.7:8443", "pw", false)
	host, port, domain, err := parseMaccServer("abcd12-"+enc+"-www.example.com", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if host != "203.0.113.7" || port != "8443" || domain != "www.example.com" {
		t.Fatalf("bad: %s %s %s", host, port, domain)
	}
}

func TestParseMaccServerBase64(t *testing.T) {
	C.MaccSalt = "test-salt"
	enc := testEncryptDescriptor("198.51.100.9:443", "pw", true)
	host, _, _, err := parseMaccServer("xx-"+enc+"-cdn.example.net", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if host != "198.51.100.9" {
		t.Fatal(host)
	}
}

func TestMaccNewFromOption(t *testing.T) {
	C.MaccSalt = "test-salt"
	enc := testEncryptDescriptor("127.0.0.1:1080", "secret", false)
	m, err := NewMacc(MaccOption{
		Name:     "macc-test",
		Address:  "aa-" + enc + "-dummy.example.com",
		Password: "secret",
		Cipher:   "aes-256-cfb",
		UDP:      true,
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

func TestMaccSaltGuard(t *testing.T) {
	old := C.MaccSalt
	C.MaccSalt = ""
	defer func() { C.MaccSalt = old }()
	_, err := NewMacc(MaccOption{Address: "a-b-c", Cipher: "dummy"})
	if err == nil || !strings.Contains(err.Error(), "MaccSalt not set") {
		t.Fatalf("salt guard: %v", err)
	}
}
