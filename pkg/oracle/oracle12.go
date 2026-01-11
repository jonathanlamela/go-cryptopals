package oracle

import (
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
)

// Oracle12 implements Challenge 12: Byte-at-a-time ECB decryption.
// Appends a secret suffix to user input before encrypting with ECB.
// Attacker must recover the suffix one byte at a time.
type Oracle12 struct {
	Key    []byte
	Suffix []byte
}

func NewOracle12(suffix []byte) *Oracle12 {
	return &Oracle12{Key: randomBytes(16), Suffix: append([]byte(nil), suffix...)}
}

// Encrypt appends the secret suffix and encrypts with ECB mode.
// The attacker can control the prefix to align blocks and discover the suffix.
func (o *Oracle12) Encrypt(input []byte) ([]byte, error) {
	// Concatenate user input with secret suffix
	data := append(append([]byte(nil), input...), o.Suffix...)
	return cu.CryptoBytes(data).SSLECBEncrypt(o.Key, true)
}

func (o *Oracle12) GetSuffix() []byte { return append([]byte(nil), o.Suffix...) }
