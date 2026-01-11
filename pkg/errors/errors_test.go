package errors

import (
	"testing"
)

func TestErrorVariables(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrInvalidHEXValue",
			err:  ErrInvalidHEXValue,
			want: "invalid hex value",
		},
		{
			name: "ErrInvalidHEXToBytesConversion",
			err:  ErrInvalidHEXToBytesConversion,
			want: "invalid hex to bytes conversion",
		},
		{
			name: "ErrInvalidHEXToBase64Conversion",
			err:  ErrInvalidHEXToBase64Conversion,
			want: "invalid hex to base64 conversion",
		},
		{
			name: "ErrInvalidBytesToHEX",
			err:  ErrInvalidBytesToHEX,
			want: "invalid bytes to hex",
		},
		{
			name: "ErrInvalidBase64ToBytes",
			err:  ErrInvalidBase64ToBytes,
			want: "invalid base64 to bytes",
		},
		{
			name: "ErrUnableFindKs",
			err:  ErrUnableFindKs,
			want: "unable to find key size",
		},
		{
			name: "ErrBreakRepeatingKeyAttackFailed",
			err:  ErrBreakRepeatingKeyAttackFailed,
			want: "break repeating key attack failed",
		},
		{
			name: "ErrPKCS7PaddingFailed",
			err:  ErrPKCS7PaddingFailed,
			want: "pkcs7 padding failed",
		},
		{
			name: "ErrInvalidPadding",
			err:  ErrInvalidPadding,
			want: "invalid padding",
		},
		{
			name: "ErrBadKeySize",
			err:  ErrBadKeySize,
			want: "bad key size",
		},
		{
			name: "ErrBadIvSize",
			err:  ErrBadIvSize,
			want: "bad iv size",
		},
		{
			name: "ErrECBEncryptionFailed",
			err:  ErrECBEncryptionFailed,
			want: "ecb encryption failed",
		},
		{
			name: "ErrCBCEncryptionFailed",
			err:  ErrCBCEncryptionFailed,
			want: "cbc encryption failed",
		},
		{
			name: "ErrFailedAesCtrEncrypt",
			err:  ErrFailedAesCtrEncrypt,
			want: "failed aes ctr encrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("Error message mismatch: got %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}

func TestErrorsAreNotNil(t *testing.T) {
	if ErrInvalidHEXValue == nil {
		t.Error("ErrInvalidHEXValue should not be nil")
	}
	if ErrInvalidBase64ToBytes == nil {
		t.Error("ErrInvalidBase64ToBytes should not be nil")
	}
	if ErrPKCS7PaddingFailed == nil {
		t.Error("ErrPKCS7PaddingFailed should not be nil")
	}
	if ErrCBCEncryptionFailed == nil {
		t.Error("ErrCBCEncryptionFailed should not be nil")
	}
}
