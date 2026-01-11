package oracle

import (
	b64 "github.com/jonathanlamela/go-cryptopals/pkg/base64"
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
)

// Oracle17 implements CBC padding oracle attack (Challenge 17)
// Encrypts random tokens and provides a padding validation oracle.
// Attacker can use the oracle to decrypt ciphertext without knowing the key.
type Oracle17 struct {
	Key    []byte
	Tokens []string
}

func NewOracle17() *Oracle17 {
	tokens := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	return &Oracle17{
		Key:    randomBytes(16),
		Tokens: tokens,
	}
}

// EncryptToken encrypts a random token from the list using CBC mode.
// Returns the ciphertext and the IV used for encryption.
// Uses PKCS#7 padding to align plaintext to block size (16 bytes).
func (o *Oracle17) EncryptToken(index int) ([]byte, []byte) {
	if index < 0 || index >= len(o.Tokens) {
		return nil, nil
	}

	// Decode the base64 token to get plaintext bytes
	plaintext, _ := b64.FromString(o.Tokens[index]).ToBytes()
	// Generate random IV for this encryption
	iv := randomBytes(16)
	// Encrypt with CBC mode and PKCS#7 padding
	ciphertext, _ := cu.CryptoBytes(plaintext).SSLCBCEncrypt(o.Key, iv, true)
	return ciphertext, iv
}

// DecryptToken returns the decrypted plaintext for a specific token.
// Used for testing/validation purposes only (attacker shouldn't have this!).
func (o *Oracle17) DecryptToken(index int) []byte {
	if index < 0 || index >= len(o.Tokens) {
		return nil
	}
	plaintext, _ := b64.FromString(o.Tokens[index]).ToBytes()
	return plaintext
}

// CheckPadding is the padding oracle - the vulnerability that enables the attack.
// Returns true if ciphertext decrypts to valid PKCS#7 padding, false otherwise.
// This information leak allows attackers to decrypt without knowing the key!
// The oracle reveals whether the last bytes form valid padding (e.g., \x01, \x02\x02, \x03\x03\x03).
func (o *Oracle17) CheckPadding(ciphertext, iv []byte) bool {
	// Decrypt with CBC mode and check if padding is valid
	decrypted, err := cu.CryptoBytes(ciphertext).SSLCBCDecrypt(o.Key, iv, true)
	// Return true only if decryption succeeded and padding was valid
	return err == nil && len(decrypted) > 0
}
