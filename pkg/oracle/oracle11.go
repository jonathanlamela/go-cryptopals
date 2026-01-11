package oracle

import (
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
)

// Oracle11 implements Challenge 11: ECB/CBC detection oracle.
// Randomly chooses between ECB and CBC mode for encryption.
// Attacker must detect which mode is being used.
type Oracle11 struct {
	Key    []byte
	UseCBC bool
	IV     []byte
}

func NewOracle11() *Oracle11 {
	useCBC := randomInt(0, 1) == 1
	iv := randomBytes(16)
	return &Oracle11{Key: randomBytes(16), UseCBC: useCBC, IV: iv}
}

// Encrypt adds random padding and encrypts with either ECB or CBC mode.
// The random prefix/suffix makes detection harder but ECB still shows patterns.
func (o *Oracle11) Encrypt(input []byte) ([]byte, error) {
	// Add 5-10 random bytes before and after input
	prefix := randomBytes(randomInt(5, 10))
	suffix := randomBytes(randomInt(5, 10))
	data := append(append(prefix, input...), suffix...)

	if o.UseCBC {
		return cu.CryptoBytes(data).SSLCBCEncrypt(o.Key, o.IV, true)
	}
	return cu.CryptoBytes(data).SSLECBEncrypt(o.Key, true)
}

func (o *Oracle11) IsCBC() bool { return o.UseCBC }
func (o *Oracle11) IsECB() bool { return !o.UseCBC }

// IsEcbCalculated detects ECB mode by looking for repeated ciphertext blocks.
// ECB encrypts identical plaintext blocks to identical ciphertext blocks.
func (o *Oracle11) IsEcbCalculated(ct []byte) bool {
	return cu.ContainsDuplicateChunks(ct, 16)
}
