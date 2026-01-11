package set3

import (
	"bufio"
	"os"
	"strings"
	"testing"

	b64 "github.com/jonathanlamela/go-cryptopals/pkg/base64"
	cu "github.com/jonathanlamela/go-cryptopals/pkg/cryptoutil"
	or "github.com/jonathanlamela/go-cryptopals/pkg/oracle"
)

func TestChallenge17(t *testing.T) {
	// Challenge 17: CBC Padding Oracle Attack
	// This attack exploits the fact that a server reveals whether padding is valid.
	// By manipulating the IV (or previous ciphertext block), we can deduce plaintext bytes.
	//
	// How it works:
	// 1. For each byte position (right to left), we try all 256 possible values
	// 2. We modify the IV/prev block and check if the resulting plaintext has valid padding
	// 3. When padding is valid, we can deduce: plaintext_byte = padding_value XOR our_test_value
	// 4. We repeat for all bytes in all blocks

	const blockSize = 16

	// Setup: Get a plaintext token and create random key/IV for encryption
	oracle := or.NewOracle17()
	plainBytes := oracle.DecryptToken(8) // Get token at index 8: "000008ollin' in my five point oh"
	key := cu.RandomBytes(blockSize)     // Random 16-byte AES key
	iv := cu.RandomBytes(blockSize)      // Random 16-byte initialization vector

	// Encrypt WITHOUT automatic padding (pad=false) because plaintext length may not be a multiple of 16
	// This simulates a real-world scenario where padding is handled separately
	ciphertext, err := cu.CryptoBytes(plainBytes).SSLCBCEncrypt(key, iv, false)
	if err != nil {
		t.Fatal(err)
	}

	// Attack: Decrypt the ciphertext byte-by-byte using padding oracle
	cleartext := make([]byte, len(ciphertext)) // Will hold our recovered plaintext
	prev := make([]byte, blockSize)            // IV for first block, then each ciphertext block
	copy(prev, iv)                             // Start with the actual IV

	// Process each 16-byte block of ciphertext
	for blockIdx := 0; blockIdx < len(ciphertext)/blockSize; blockIdx++ {
		block := ciphertext[blockIdx*blockSize : (blockIdx+1)*blockSize] // Current ciphertext block
		blockOffset := blockIdx * blockSize                              // Offset in cleartext array

		// Process each byte in the block, from right to left (15 -> 0)
		// This is because PKCS#7 padding works from the end
		for i := blockSize - 1; i >= 0; i-- {
			// The padding value we're forcing the plaintext to have
			// For the last byte: padding=1, second-to-last: padding=2, etc.
			padding := byte(blockSize - i)

			// Prepare prev block: XOR already-found bytes to transition to new padding value
			// If we previously had padding=1 and now want padding=2, we XOR with 1^2=3
			// This updates bytes i+1..15 so they decrypt to the new padding value
			trans := (padding - 1) ^ padding
			for j := i + 1; j < blockSize; j++ {
				prev[j] ^= trans // Transition each byte to new padding
			}

			// Try all 256 possible values for prev[i]
			found := false
			for u := 0; u <= 255; u++ {
				prev[i] ^= byte(u) // Apply test value

				// Oracle check: Does the decryption have valid PKCS#7 padding?
				// If yes, the last 'padding' bytes all equal 'padding'
				_, err := cu.CryptoBytes(block).SSLCBCDecrypt(key, prev, true)
				isValid := err == nil

				if isValid {
					// Special case: For the last byte, we might get false positives
					// A byte that decrypts to 0x02 0x02 looks like valid padding=2
					// To verify it's really padding=1, we flip the previous byte and check again
					if i == blockSize-1 && i > 0 {
						prev[i-1] ^= 1 // Flip one bit in previous byte
						_, err2 := cu.CryptoBytes(block).SSLCBCDecrypt(key, prev, true)
						prev[i-1] ^= 1 // Restore original value
						if err2 != nil {
							// If flipping prev byte breaks padding, our guess was wrong
							prev[i] ^= byte(u) // Undo the XOR
							continue           // Try next value
						}
					}

					// Found the correct value!
					// Plaintext byte = padding_value XOR test_value (because CBC: P = D(C) XOR IV)
					cleartext[blockOffset+i] = padding ^ byte(u)
					found = true
					break
				}

				prev[i] ^= byte(u) // Undo the XOR for next iteration
			}

			if !found {
				t.Fatalf("Failed at block %d, position %d", blockIdx, i)
			}
		}

		copy(prev, block)
	}

	// Decrypt both and compare
	decrypted1, _ := cu.CryptoBytes(plainBytes).SSLCBCDecrypt(key, iv, false)
	decrypted2, _ := cu.CryptoBytes(cleartext).SSLCBCDecrypt(key, iv, false)

	if string(decrypted1) != string(decrypted2) {
		t.Fatalf("Mismatch:\nExpected: %q\nGot:      %q", string(decrypted1), string(decrypted2))
	}
}

func TestChallenge18(t *testing.T) {
	data := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	ciphertext, _ := b64.FromString(data).ToBytes()
	key := []byte("YELLOW SUBMARINE")
	cleartext, err := cu.CryptoBytes(ciphertext).NonceCTREncrypt(key, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	result := string(cleartext)
	expected := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	if result != expected {
		t.Fatalf("CTR decryption failed: got %q, want %q", result, expected)
	}
}

func TestChallenge19(t *testing.T) {
	const blockSize = 16
	key := cu.RandomBytes(blockSize)
	file, err := os.Open("../../data/data_19.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var results [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineBytes, err := b64.FromString(line).ToBytes()
		if err != nil {
			continue
		}
		encrypted, err := cu.CryptoBytes(lineBytes).NonceCTREncrypt(key, make([]byte, 8))
		if err != nil {
			continue
		}
		results = append(results, encrypted)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("No results produced")
	}
}

func TestChallenge20(t *testing.T) {
	const blockSize = 16
	key := cu.RandomBytes(blockSize)
	file, err := os.Open("../../data/data_20.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var results [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineBytes, err := b64.FromString(line).ToBytes()
		if err != nil {
			continue
		}
		encrypted, err := cu.CryptoBytes(lineBytes).NonceCTREncrypt(key, make([]byte, 8))
		if err != nil {
			continue
		}
		results = append(results, encrypted)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("No ciphertexts generated")
	}
	minLen := len(results[0])
	for _, ct := range results {
		if len(ct) < minLen {
			minLen = len(ct)
		}
	}
	for i := range results {
		results[i] = results[i][:minLen]
	}
	transposed := make([][]byte, minLen)
	for i := 0; i < minLen; i++ {
		transposed[i] = make([]byte, len(results))
		for j, ct := range results {
			transposed[i][j] = ct[i]
		}
	}
	var keyVec []byte
	for _, block := range transposed {
		result := cu.CryptoBytes(block).EvaluateFrequency()
		if result != nil {
			keyVec = append(keyVec, result.Key)
		}
	}
	var flatResult []byte
	for _, ct := range results {
		flatResult = append(flatResult, ct...)
	}
	decrypted := cu.CryptoBytes(flatResult).RepeatingKeyXOR(keyVec)
	plaintext := string(decrypted)
	if !strings.Contains(plaintext, "I'm rated") {
		t.Fatalf("Challenge 20 failed: decrypted text doesn't contain expected phrase")
	}
}
