package errors

import "errors"

var (
	ErrInvalidHEXValue              = errors.New("invalid hex value")
	ErrInvalidHEXToBytesConversion  = errors.New("invalid hex to bytes conversion")
	ErrInvalidHEXToBase64Conversion = errors.New("invalid hex to base64 conversion")
	ErrInvalidBytesToHEX            = errors.New("invalid bytes to hex")
	ErrInvalidBase64ToBytes         = errors.New("invalid base64 to bytes")

	ErrUnableFindKs                  = errors.New("unable to find key size")
	ErrBreakRepeatingKeyAttackFailed = errors.New("break repeating key attack failed")

	ErrPKCS7PaddingFailed = errors.New("pkcs7 padding failed")
	ErrInvalidPadding     = errors.New("invalid padding")

	ErrBadKeySize          = errors.New("bad key size")
	ErrBadIvSize           = errors.New("bad iv size")
	ErrECBEncryptionFailed = errors.New("ecb encryption failed")
	ErrCBCEncryptionFailed = errors.New("cbc encryption failed")
	ErrFailedAesCtrEncrypt = errors.New("failed aes ctr encrypt")
)
