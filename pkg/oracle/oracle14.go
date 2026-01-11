package oracle

import (
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
)

// Oracle14 implements Challenge 14: Byte-at-a-time ECB decryption with random prefix.
// Similar to Oracle12 but adds a random prefix before user input.
// Attacker must account for the random prefix alignment.
type Oracle14 struct {
	Key    []byte
	Prefix []byte
	Suffix []byte
}

func NewOracle14(suffix []byte) *Oracle14 {
	return &Oracle14{
		Key:    randomBytes(16),
		Prefix: randomBytes(randomInt(5, 50)),
		Suffix: append([]byte(nil), suffix...),
	}
}

// Encrypt prepends a random prefix and appends suffix, then encrypts with ECB.
// The attacker must account for the prefix length in their decryption strategy.
func (o *Oracle14) Encrypt(input []byte) ([]byte, error) {
	data := make([]byte, 0, len(o.Prefix)+len(input)+len(o.Suffix))
	data = append(data, o.Prefix...)
	data = append(data, input...)
	data = append(data, o.Suffix...)
	return cu.CryptoBytes(data).SSLECBEncrypt(o.Key, true)
}

func (o *Oracle14) GetSuffix() []byte { return append([]byte(nil), o.Suffix...) }
