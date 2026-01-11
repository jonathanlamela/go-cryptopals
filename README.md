# Cryptopals Challenges - Go Implementation

This is a Go port of the Cryptopals Crypto Challenges, migrated from the original Rust implementation in `../rust-cryptopals`.

## Project Structure

```markdown
go-cryptopals/
├── go.mod                  # Go module definition
├── pkg/                    # Reusable packages
│   ├── base64/            # Base64 encoding/decoding
│   ├── hex/               # Hex encoding/decoding and conversion
│   ├── cryptoutil/        # Core cryptographic utilities
│   ├── errors/            # Error definitions
│   └── oracle/            # Oracle implementations for challenges
├── internal/              # Challenge test suites
│   ├── set1/             # Set 1: Basics
│   ├── set2/             # Set 2: Block crypto
│   └── set3/             # Set 3: Block & stream crypto
└── data/                  # Input data files for challenges
```

## Features

### Set 1: Basics

- ✅ Challenge 1: Convert hex to base64
- ✅ Challenge 2: Fixed XOR
- ✅ Challenge 3: Single-byte XOR cipher
- ✅ Challenge 4: Detect single-character XOR
- ✅ Challenge 5: Implement repeating-key XOR
- ✅ Challenge 6: Break repeating-key XOR
- ✅ Challenge 7: AES in ECB mode
- ✅ Challenge 8: Detect AES in ECB mode

### Set 2: Block Crypto

- ✅ Challenge 9: Implement PKCS#7 padding
- ✅ Challenge 10: Implement CBC mode
- ✅ Challenge 11: ECB/CBC detection oracle
- ✅ Challenge 12: Byte-at-a-time ECB decryption (Simple)
- ✅ Challenge 13: ECB cut-and-paste
- ✅ Challenge 14: Byte-at-a-time ECB decryption (Harder)
- ✅ Challenge 15: PKCS#7 padding validation
- ✅ Challenge 16: CBC bitflipping attacks

### Set 3: Block & Stream Crypto

- ⏸️ Challenge 17: CBC padding oracle (skipped - complex implementation)
- ✅ Challenge 18: Implement CTR mode
- ✅ Challenge 19: Break fixed-nonce CTR mode (basic test)
- ✅ Challenge 20: Break fixed-nonce CTR statistically

## Core Utilities

### `pkg/cryptoutil`

- **XOR operations**: Single-byte and repeating-key XOR
- **Frequency analysis**: English text scoring for cryptanalysis
- **Hamming distance**: For key size detection
- **PKCS#7 padding**: Padding and validation
- **AES modes**: ECB, CBC, CTR
- **Nonce-CTR**: Custom CTR with nonce + counter
- **ECB detection**: Duplicate block detection
- **Random bytes**: Cryptographically secure random generation

### `pkg/oracle`

- **Oracle11**: ECB/CBC detection oracle
- **Oracle12**: Suffix ECB oracle (Challenge 12)
- **Oracle13**: Profile encoding/ECB cut-and-paste (Challenge 13)
- **Oracle14**: Random-prefix ECB oracle (Challenge 14)
- **Oracle17**: CBC padding oracle (Challenge 17)

### `pkg/hex` & `pkg/base64`

- Type-safe wrappers for hex and base64 encoding
- Conversion between formats
- Validation and error handling

## Running the Tests

```bash
# Run all tests
go test ./...

# Run specific set
go test ./internal/set1
go test ./internal/set2
go test ./internal/set3

# Run with verbose output
go test -v ./...

# Run specific challenge
go test ./internal/set1 -run TestChallenge3
```

## Implementation Notes

### Porting from Rust

This project was ported from Rust to Go, maintaining functional parity with the original implementation while adapting to Go idioms:

- **Error handling**: Rust's `Result<T, E>` pattern mapped to Go's `(T, error)` convention
- **Method receivers**: Rust traits implemented as Go methods on custom types
- **Crypto libraries**: Rust's `crypto` crate replaced with Go's `crypto/*` standard library packages
- **Memory safety**: Rust's ownership model adapted to Go's garbage collection with explicit copying where needed

### Key Differences

- **AES CTR**: Two implementations:
  - `SSLCTREncrypt/Decrypt`: Standard CTR with 16-byte IV
  - `NonceCTREncrypt`: Custom CTR with 8-byte nonce + 8-byte little-endian counter (Challenges 19-20)
- **Padding**: Separate `Unpad` function instead of method for consistency
- **Frequency analysis**: Returns pointer to struct with score, key, and plaintext

### Test Data

Input data files are located in `data/`:

- `data_4.txt`: Hex-encoded strings (Challenge 4)
- `data_6.txt`: Base64-encoded ciphertext (Challenge 6)
- `data_7.txt`: Base64-encoded ECB ciphertext (Challenge 7)
- `data_8.txt`: Hex-encoded ciphertexts (Challenge 8)
- `data_10.txt`: Base64-encoded CBC ciphertext (Challenge 10)
- `data_19.txt`: Base64-encoded plaintexts (Challenge 19)
- `data_20.txt`: Base64-encoded plaintexts (Challenge 20)

## Requirements

- Go 1.21 or later

## License

This is an educational project based on the Cryptopals Crypto Challenges.
