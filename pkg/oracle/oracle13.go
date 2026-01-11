package oracle

import (
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
)

// Oracle13 implements Challenge 13: ECB cut-and-paste attack.
// Encrypts a profile object where attacker can control the email field.
// Attacker can manipulate encrypted blocks to escalate privileges.
type Oracle13 struct {
	Key []byte
}

func NewOracle13() *Oracle13 { return &Oracle13{Key: randomBytes(16)} }

// sanitizeEmail removes dangerous characters from email addresses.
// Removes & and = to prevent tampering with the profile format.
func sanitizeEmail(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '&' || s[i] == '=' {
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// ProfileFor creates a profile string for the given email.
// Format: "email=<email>&uid=10&role=user"
func (o *Oracle13) ProfileFor(email string) string {
	e := sanitizeEmail(email)
	return "email=" + e + "&uid=10&role=user"
}

// Encrypt encrypts the profile data using ECB mode.
func (o *Oracle13) Encrypt(b []byte) ([]byte, error) {
	return cu.CryptoBytes(b).SSLECBEncrypt(o.Key, true)
}
