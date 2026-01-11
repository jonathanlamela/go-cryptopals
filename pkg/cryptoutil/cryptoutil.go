package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math"
	"sort"

	"github.com/jonathanlamela/go-cryptopals/pkg/errors"
)

type CryptoBytes []byte

var letterFrequencies = [26]float64{
	8.34, 1.54, 2.73, 4.14, 12.60, 2.03, 1.92, 6.11, 6.71, 0.23, 0.87, 4.24, 2.53,
	6.80, 7.70, 1.66, 0.09, 5.68, 6.11, 9.37, 2.85, 1.06, 2.34, 0.20, 2.04, 0.06,
}

// RandomBytes generates n random bytes
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func unicodeLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// EvaluateScore scores text based on how likely it is to be English.
// Uses letter frequency analysis: English text has predictable letter distributions.
// Returns nil if text contains non-printable characters, otherwise returns a score.
// Higher scores indicate more English-like text.
func (c CryptoBytes) EvaluateScore() *float64 {
	score := 0.0

	// First pass: Check all bytes are printable (ASCII 32-126 or whitespace)
	for _, b := range c {
		// Reject text with non-printable characters
		if !((b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' || b == ' ') {
			return nil
		}
	}

	// Second pass: Score based on English letter frequency
	// Common letters like 'e', 't', 'a' contribute higher scores
	for _, b := range c {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			i := unicodeLower(b) - 'a'
			// Use log of frequency to avoid numerical issues
			score += math.Log10(letterFrequencies[int(i)])
		}
	}
	return &score
}

// Xor performs XOR operation between two byte slices.
// XOR is the fundamental operation in many ciphers: A XOR B XOR B = A
// Returns result truncated to length of shorter input.
func (c CryptoBytes) Xor(v2 []byte) []byte {
	// Use length of shorter slice
	n := len(c)
	if len(v2) < n {
		n = len(v2)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = c[i] ^ v2[i]
	}
	return out
}

// XorSingle XORs every byte with the same key byte.
// This is a single-byte XOR cipher, one of the simplest encryption methods.
func (c CryptoBytes) XorSingle(k byte) []byte {
	out := make([]byte, len(c))
	for i := range c {
		out[i] = c[i] ^ k
	}
	return out
}

// RepeatingKeyXOR implements the Vigenère cipher using XOR.
// Each byte is XORed with the corresponding key byte (cycling through the key).
// For example, with key "ABC": plaintext[0]^A, plaintext[1]^B, plaintext[2]^C, plaintext[3]^A, ...
func (c CryptoBytes) RepeatingKeyXOR(key []byte) []byte {
	out := make([]byte, len(c))
	for i := range c {
		// Use modulo to cycle through key
		out[i] = c[i] ^ key[i%len(key)]
	}
	return out
}

// bitsOnesCount8 counts the number of 1-bits in a byte.
// Used for calculating Hamming distance (number of differing bits).
func bitsOnesCount8(x byte) int {
	count := 0
	v := x
	for v != 0 {
		v &= v - 1
		count++
	}
	return count
}

// ComputeDistanceBytes calculates the Hamming distance between two byte slices.
// Hamming distance = number of bits that differ between the two inputs.
// Used in cryptanalysis to find patterns in ciphertext.
func (c CryptoBytes) ComputeDistanceBytes(b []byte) uint32 {
	// Compare only up to the length of shorter slice
	n := len(c)
	if len(b) < n {
		n = len(b)
	}
	var dist uint32
	for i := 0; i < n; i++ {
		// XOR gives 1-bits where inputs differ, count those bits
		dist += uint32(bitsOnesCount8(c[i] ^ b[i]))
	}
	return dist
}

func chunkBytes(b []byte, size int) [][]byte {
	var out [][]byte
	for i := 0; i < len(b); i += size {
		end := i + size
		if end > len(b) {
			end = len(b)
		}
		out = append(out, b[i:end])
	}
	return out
}

// FindKS finds the most likely key size for a repeating-key XOR cipher.
// Uses the Hamming distance (edit distance) between chunks of ciphertext.
// The correct key size will have a smaller normalized Hamming distance because
// bytes at the same position in the key will have been XORed with the same key byte.
func (c CryptoBytes) FindKS() (int, error) {
	var outKS int
	outDist := math.Inf(+1) // Start with infinite distance

	// Try key sizes from 2 to 40
	for ks := 2; ks < 40; ks++ {
		chunks := chunkBytes([]byte(c), ks)
		if len(chunks) < 4 {
			continue // Need at least 4 chunks for comparison
		}

		// Compare first 4 chunks pairwise
		b1, b2, b3, b4 := chunks[0], chunks[1], chunks[2], chunks[3]

		// Calculate average normalized Hamming distance between all pairs
		// Normalized by key size to make different key sizes comparable
		ds := float64(CryptoBytes(b1).ComputeDistanceBytes(b2)+CryptoBytes(b1).ComputeDistanceBytes(b3)+CryptoBytes(b1).ComputeDistanceBytes(b4)+CryptoBytes(b2).ComputeDistanceBytes(b3)+CryptoBytes(b2).ComputeDistanceBytes(b4)+CryptoBytes(b3).ComputeDistanceBytes(b4)) / (6.0 * float64(ks))

		// Keep the key size with minimum distance
		if ds < outDist {
			outDist = ds
			outKS = ks
		}
	}
	if outKS == 0 {
		return 0, errors.ErrUnableFindKs
	}
	return outKS, nil
}

// EvaluateFrequency attempts single-byte XOR decryption by trying all 256 possible keys.
// For each key, it XORs the ciphertext and scores the result based on English letter frequency.
// Returns the key, plaintext, and score for the most English-like result.
// This is used to break single-byte XOR ciphers.
func (c CryptoBytes) EvaluateFrequency() *struct {
	Score float64
	Key   byte
	Plain []byte
} {
	var best *struct {
		Score float64
		Key   byte
		Plain []byte
	}
	// Try all 256 possible single-byte XOR keys
	for k := 0; k <= 255; k++ {
		// XOR the ciphertext with this key
		plain := c.XorSingle(byte(k))
		// Score the result based on English letter frequency
		if score := CryptoBytes(plain).EvaluateScore(); score != nil {
			// Keep track of the best scoring result
			if best == nil || *score > best.Score {
				best = &struct {
					Score float64
					Key   byte
					Plain []byte
				}{Score: *score, Key: byte(k), Plain: plain}
			}
		}
	}
	return best
}

// RepeatingXORAttack breaks a repeating-key XOR cipher.
// Strategy:
//  1. Find the most likely key size using Hamming distance
//  2. Transpose ciphertext into blocks (all bytes encrypted with same key byte)
//  3. Use frequency analysis on each block to find that key byte
//  4. Reconstruct the full key and decrypt
func (c CryptoBytes) RepeatingXORAttack() (string, error) {
	// Step 1: Find most likely key size
	ks, err := c.FindKS()
	if err != nil {
		return "", err
	}

	// Step 2: Transpose ciphertext
	// If key size is 3, group bytes [0,3,6,9...], [1,4,7,10...], [2,5,8,11...]
	// Each group was encrypted with the same key byte
	transposed := make([][]byte, ks)
	for i := 0; i+ks <= len(c); i += ks {
		block := c[i : i+ks]
		for j := 0; j < ks; j++ {
			transposed[j] = append(transposed[j], block[j])
		}
	}

	// Step 3: Find key byte for each position using frequency analysis
	key := make([]byte, 0, ks)
	for _, bl := range transposed {
		res := CryptoBytes(bl).EvaluateFrequency()
		if res != nil {
			key = append(key, res.Key)
		}
	}
	if len(key) == 0 {
		return "", errors.ErrBreakRepeatingKeyAttackFailed
	}
	plain := c.RepeatingKeyXOR(key)
	return string(plain), nil
}

func (c *CryptoBytes) Pad(k int) error {
	if k < 2 {
		return errors.ErrPKCS7PaddingFailed
	}
	p := k - (len(*c) % k)
	for i := 0; i < p; i++ {
		*c = append(*c, byte(p))
	}
	return nil
}

// PKCS7Pad pads data to a multiple of k bytes using PKCS#7 padding scheme.
// PKCS#7 padding works by adding N bytes of value N to reach the block size.
// For example, if we need 3 bytes of padding, we add three bytes each with value 0x03.
// If the data is already a multiple of k, we add a full block of padding (k bytes of value k).
func PKCS7Pad(b []byte, k int) []byte {
	// Calculate how many bytes of padding we need
	p := k - (len(b) % k)

	// Create output slice with room for original data + padding
	out := make([]byte, len(b)+p)
	copy(out, b)

	// Fill padding bytes with the padding length value
	for i := len(b); i < len(out); i++ {
		out[i] = byte(p)
	}
	return out
}

// CheckPaddingValid verifies that data has valid PKCS#7 padding.
// Valid padding means:
// 1. The last byte indicates the padding length (1 to k)
// 2. All padding bytes have the same value (equal to padding length)
// For example: [... data ... 0x04 0x04 0x04 0x04] has 4 bytes of padding
func CheckPaddingValid(b []byte, k int) error {
	// Basic sanity checks
	if k < 2 || len(b) == 0 || len(b)%k != 0 {
		return errors.ErrInvalidPadding
	}

	// Read padding length from last byte
	pad := int(b[len(b)-1])

	// Verify padding length is reasonable
	if pad < 1 || pad > k || pad > len(b) {
		return errors.ErrInvalidPadding
	}

	// Verify all padding bytes have the correct value
	for i := len(b) - pad; i < len(b); i++ {
		if b[i] != byte(pad) {
			return errors.ErrInvalidPadding
		}
	}
	return nil
}

// Unpad removes PKCS#7 padding from data.
// First validates the padding, then returns data with padding bytes removed.
func Unpad(b []byte, k int) ([]byte, error) {
	// Verify padding is valid
	if err := CheckPaddingValid(b, k); err != nil {
		return nil, err
	}
	// Remove the padding bytes (last N bytes where N is the padding value)
	return b[:len(b)-int(b[len(b)-1])], nil
}

func (c CryptoBytes) SSLECBEncrypt(key []byte, pad bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.ErrBadKeySize
	}
	src := []byte(c)
	block, _ := aes.NewCipher(key)
	if pad {
		src = PKCS7Pad(src, block.BlockSize())
	} else if len(src)%block.BlockSize() != 0 {
		return nil, errors.ErrECBEncryptionFailed
	}
	out := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		block.Encrypt(out[i:i+block.BlockSize()], src[i:i+block.BlockSize()])
	}
	return out, nil
}

func (c CryptoBytes) SSLECBDecrypt(key []byte, pad bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.ErrBadKeySize
	}
	src := []byte(c)
	if !pad && len(src)%aes.BlockSize != 0 {
		return nil, errors.ErrECBEncryptionFailed
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		block.Decrypt(out[i:i+block.BlockSize()], src[i:i+block.BlockSize()])
	}
	if pad {
		var err error
		out, err = Unpad(out, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SSLCBCEncrypt encrypts data using AES in CBC (Cipher Block Chaining) mode.
// CBC mode works by XORing each plaintext block with the previous ciphertext block
// before encryption. The first block is XORed with the IV (Initialization Vector).
//
// Parameters:
//   key: 16-byte AES-128 key
//   iv:  16-byte initialization vector (must be random for security)
//   pad: if true, applies PKCS#7 padding; if false, data must be multiple of 16 bytes
func (c CryptoBytes) SSLCBCEncrypt(key, iv []byte, pad bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.ErrBadKeySize
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.ErrBadIvSize
	}
	src := []byte(c)
	block, _ := aes.NewCipher(key)
	// Apply PKCS#7 padding if requested
	if pad {
		src = PKCS7Pad(src, block.BlockSize())
	} else if len(src)%block.BlockSize() != 0 {
		return nil, errors.ErrCBCEncryptionFailed
	}
	out := make([]byte, len(src))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, src)
	return out, nil
}

// SSLCBCDecrypt decrypts data using AES in CBC mode.
// CBC decryption works by decrypting each block, then XORing with the previous
// ciphertext block (or IV for the first block) to recover the plaintext.
//
// Parameters:
//   key: 16-byte AES-128 key
//   iv:  16-byte initialization vector (must match encryption IV)
//   pad: if true, removes and validates PKCS#7 padding after decryption
func (c CryptoBytes) SSLCBCDecrypt(key, iv []byte, pad bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.ErrBadKeySize
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.ErrBadIvSize
	}
	src := []byte(c)
	// If not expecting padding, data must be multiple of block size
	if !pad && len(src)%aes.BlockSize != 0 {
		return nil, errors.ErrCBCEncryptionFailed
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	// Use Go's CBC mode for decryption
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, src)
	// Remove and validate padding if requested
	if pad {
		var err error
		out, err = Unpad(out, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SSLCTREncrypt encrypts data using AES in CTR (Counter) mode.
// CTR mode turns a block cipher into a stream cipher by encrypting a counter
// and XORing the result with the plaintext. It's symmetric: encryption = decryption.
//
// Parameters:
//   key: 16-byte AES-128 key
//   iv:  16-byte initialization vector (used as initial counter value)
func (c CryptoBytes) SSLCTREncrypt(key []byte, iv []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, len(c))
	stream.XORKeyStream(out, []byte(c))
	return out, nil
}

// SSLCTRDecrypt decrypts data using AES in CTR mode.
// Since CTR mode is symmetric (XOR-based), decryption is identical to encryption.
func (c CryptoBytes) SSLCTRDecrypt(key []byte, iv []byte) ([]byte, error) {
	return c.SSLCTREncrypt(key, iv)
}

func (c CryptoBytes) NonceCTREncrypt(key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.ErrFailedAesCtrEncrypt
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, 0, len(c))
	for count, i := 0, 0; i < len(c); i += 16 {
		end := i + 16
		if end > len(c) {
			end = len(c)
		}
		bs := end - i
		counterBlock := make([]byte, 16)
		copy(counterBlock[:8], nonce)
		cb := uint64(count)
		for j := 0; j < 8; j++ {
			counterBlock[8+j] = byte(cb >> (8 * j))
		}
		keystream := make([]byte, 16)
		block.Encrypt(keystream, counterBlock)
		x := make([]byte, bs)
		for j := 0; j < bs; j++ {
			x[j] = keystream[j] ^ c[i+j]
		}
		out = append(out, x...)
		count++
	}
	return out, nil
}

func ContainsDuplicateChunks(line []byte, chunkSize int) bool {
	if chunkSize <= 0 || len(line) < chunkSize {
		return false
	}
	var chunks [][]byte
	for i := 0; i < len(line); i += chunkSize {
		end := i + chunkSize
		if end > len(line) {
			end = len(line)
		}
		chunks = append(chunks, append([]byte(nil), line[i:end]...))
	}
	sort.Slice(chunks, func(i, j int) bool { return string(chunks[i]) < string(chunks[j]) })
	for i := 1; i < len(chunks); i++ {
		if string(chunks[i]) == string(chunks[i-1]) {
			return true
		}
	}
	return false
}
