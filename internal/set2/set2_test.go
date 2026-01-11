package set2

import (
	"os"
	"strings"
	"testing"

	b64 "github.com/jonathanlamela/go-cryptopals/pkg/base64"
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
	or "github.com/jonathanlamela/go-cryptopals/pkg/oracle"
)

func TestChallenge9(t *testing.T) {
	s := cu.CryptoBytes([]byte("YELLOW SUBMARINE"))
	if err := (&s).Pad(20); err != nil {
		t.Fatal(err)
	}
	want := []byte{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4}
	if string(s) != string(want) {
		t.Fatalf("pad mismatch: %v != %v", []byte(s), want)
	}
}

func TestChallenge10(t *testing.T) {
	data, err := os.ReadFile("../../data/data_10.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(data), "\n", "")
	bytes, err := b64.FromString(s).ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	dec, err := cu.CryptoBytes(bytes).SSLCBCDecrypt([]byte("YELLOW SUBMARINE"), iv, true)
	if err != nil {
		t.Fatal(err)
	}
	got := string(dec)
	if !strings.HasPrefix(got, "I'm back and I'm ringin'") {
		t.Fatal("unexpected plaintext head")
	}
}

func TestChallenge11(t *testing.T) {
	o := or.NewOracle11()
	input := make([]byte, 48)
	ct, err := o.Encrypt(input)
	if err != nil {
		t.Fatal(err)
	}
	if o.IsCBC() {
		if o.IsEcbCalculated(ct) {
			t.Fatal("expected CBC, got ECB detection")
		}
	} else if o.IsECB() {
		if !o.IsEcbCalculated(ct) {
			t.Fatal("expected ECB, detection failed")
		}
	}
}

func TestChallenge12(t *testing.T) {
	sfx, err := b64.FromString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	o := or.NewOracle12(sfx)
	ct, err := o.Encrypt([]byte("A"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct)%16 != 0 {
		t.Fatal("ciphertext not multiple of block size")
	}
	if b64.FromBytes(o.GetSuffix()).String() != b64.FromString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").String() {
		t.Fatal("suffix mismatch")
	}
}

func TestChallenge13(t *testing.T) {
	o := or.NewOracle13()
	// craft admin block: "email=" + 10 bytes + "admin\x0b\x0b..." = 16 byte block with admin
	adminBlock := make([]byte, 16)
	copy(adminBlock, []byte("admin"))
	for i := 5; i < 16; i++ {
		adminBlock[i] = byte(11)
	}

	// email of 10 bytes so "email=" + email fills exactly 16 bytes
	adminEmail := string(append([]byte("AAAAAAAAAA"), adminBlock...))
	prof1 := o.ProfileFor(adminEmail)
	ct1, err := o.Encrypt([]byte(prof1))
	if err != nil {
		t.Fatal(err)
	}
	extractedAdminBlock := ct1[16:32]

	// Now craft profile where "role=" starts at block boundary
	// "email=" (6) + email + "&uid=10&role=" (13)
	// Want: 6 + len(email) + 13 = 32 so role= value starts at 32
	// So: len(email) = 13
	email := "test@test.com" // 13 chars
	prof2 := o.ProfileFor(email)
	ct2, err := o.Encrypt([]byte(prof2))
	if err != nil {
		t.Fatal(err)
	}
	// Replace the block containing "user" with our admin block
	ct2 = append(ct2[:32], extractedAdminBlock...)

	dec, err := cu.CryptoBytes(ct2).SSLECBDecrypt(o.Key, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), "role=admin") {
		t.Fatal("admin role not set")
	}
}

func TestChallenge14(t *testing.T) {
	sfx, _ := b64.FromString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").ToBytes()
	o := or.NewOracle14(sfx)
	if b64.FromBytes(o.GetSuffix()).String() != b64.FromString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").String() {
		t.Fatal("suffix mismatch")
	}
}

func TestChallenge15(t *testing.T) {
	str1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	str2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	str3 := []byte("ICE ICE BABY\x05\x05\x05\x05")

	if err := cu.CheckPaddingValid(str1, 16); err != nil {
		t.Fatal(err)
	}
	if err := cu.CheckPaddingValid(str2, 16); err == nil {
		t.Fatal("expected invalid padding for str2")
	}
	if err := cu.CheckPaddingValid(str3, 16); err == nil {
		t.Fatal("expected invalid padding for str3")
	}

	unpadded, err := cu.Unpad(str1, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(unpadded) != "ICE ICE BABY" {
		t.Fatal("wrong unpad result")
	}
}

func TestChallenge16(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")

	// First check: plaintext contains ;admin=true;
	pt1 := []byte("testing 123;admin=true;blah")
	ct1, err := cu.CryptoBytes(pt1).SSLCBCEncrypt(key, iv, true)
	if err != nil {
		t.Fatal(err)
	}
	dec1, err := cu.CryptoBytes(ct1).SSLCBCDecrypt(key, iv, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec1), ";admin=true;") {
		t.Fatal("missing admin pair in dec1")
	}

	// Bitflipping attack: craft second block to become ;admin=true;
	p2 := []byte{0, 'a', 'd', 'm', 'i', 'n', 0, 't', 'r', 'u', 'e', ';', 0, 0, 0, 0}
	pt2 := make([]byte, 16+len(p2))
	copy(pt2[:16], []byte("0123456789ABCDEF"))
	copy(pt2[16:], p2)
	ct2, err := cu.CryptoBytes(pt2).SSLCBCEncrypt(key, iv, true)
	if err != nil {
		t.Fatal(err)
	}
	ct2[0] ^= byte(';')
	ct2[6] ^= byte('=')
	dec2, err := cu.CryptoBytes(ct2).SSLCBCDecrypt(key, iv, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec2), ";admin=true;") {
		t.Fatal("bitflip injection failed")
	}
}
