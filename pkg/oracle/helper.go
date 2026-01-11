package oracle

import (
	"crypto/rand"
	"math/big"
)

// randomBytes generates n random bytes using the system's CSPRNG.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// randomInt generates a random integer between min and max (inclusive).
func randomInt(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}
