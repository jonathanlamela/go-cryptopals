package cryptoutil

import (
	"testing"
)

func TestXor(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		key   []byte
		want  []byte
	}{
		{
			name:  "simple xor",
			input: []byte{1, 2, 3},
			key:   []byte{1, 2, 3},
			want:  []byte{0, 0, 0},
		},
		{
			name:  "xor with longer key",
			input: []byte{1, 2, 3},
			key:   []byte{1, 2, 3, 4, 5},
			want:  []byte{0, 0, 0},
		},
		{
			name:  "xor with shorter key",
			input: []byte{1, 2, 3, 4, 5},
			key:   []byte{1, 2, 3},
			want:  []byte{0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CryptoBytes(tt.input).Xor(tt.key)
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Xor() got %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestXorSingle(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		keyByte byte
		want    []byte
	}{
		{
			name:    "xor single key",
			input:   []byte{1, 2, 3},
			keyByte: 1,
			want:    []byte{0, 3, 2},
		},
		{
			name:    "xor with zero",
			input:   []byte{5, 6, 7},
			keyByte: 0,
			want:    []byte{5, 6, 7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CryptoBytes(tt.input).XorSingle(tt.keyByte)
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("XorSingle() got %v, want %v", got, tt.want)
					break
				}
			}
		})
	}
}

func TestRepeatingKeyXOR(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		key   []byte
		want  []byte
	}{
		{
			name:  "repeating key xor",
			input: []byte("hello"),
			key:   []byte("key"),
			want:  []byte{3, 0, 21, 7, 10},
		},
		{
			name:  "key length 1",
			input: []byte{1, 2, 3},
			key:   []byte{1},
			want:  []byte{0, 3, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CryptoBytes(tt.input).RepeatingKeyXOR(tt.key)
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("RepeatingKeyXOR() at position %d: got %v, want %v", i, got[i], tt.want[i])
					break
				}
			}
		})
	}
}

func TestComputeDistanceBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		other []byte
		want  uint32
	}{
		{
			name:  "identical bytes",
			input: []byte{0, 0, 0},
			other: []byte{0, 0, 0},
			want:  0,
		},
		{
			name:  "different bytes",
			input: []byte{1, 0, 0},
			other: []byte{0, 0, 0},
			want:  1,
		},
		{
			name:  "hamming distance example",
			input: []byte("this is a test"),
			other: []byte("wokka wokka!!!"),
			want:  37,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CryptoBytes(tt.input).ComputeDistanceBytes(tt.other)
			if got != tt.want {
				t.Errorf("ComputeDistanceBytes() got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEvaluateScore(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantNil bool
	}{
		{
			name:    "printable text",
			input:   []byte("Hello World"),
			wantNil: false,
		},
		{
			name:    "non-printable characters",
			input:   []byte{0x00, 0x01, 0x02},
			wantNil: true,
		},
		{
			name:    "empty bytes",
			input:   []byte{},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CryptoBytes(tt.input).EvaluateScore()
			if (got == nil) != tt.wantNil {
				t.Errorf("EvaluateScore() nil = %v, wantNil %v", got == nil, tt.wantNil)
			}
		})
	}
}

func TestPKCS7Pad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		want      []byte
	}{
		{
			name:      "pad to 16",
			input:     []byte("hello"),
			blockSize: 16,
			want:      []byte("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
		},
		{
			name:      "already aligned",
			input:     []byte("hello world here"),
			blockSize: 16,
			want:      []byte("hello world here\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PKCS7Pad(tt.input, tt.blockSize)
			if string(got) != string(tt.want) {
				t.Errorf("PKCS7Pad() got len %d, want len %d", len(got), len(tt.want))
			}
		})
	}
}

func TestCheckPaddingValid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "valid padding 1 byte",
			input: []byte("hello world here\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
			want:  true,
		},
		{
			name:  "valid padding 11 bytes",
			input: []byte("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
			want:  true,
		},
		{
			name:  "invalid padding",
			input: []byte("hello\x01\x02\x03"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPaddingValid(tt.input, 16)
			got := err == nil
			if got != tt.want {
				t.Errorf("CheckPaddingValid() got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:  "unpad simple",
			input: []byte("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"),
			want:  []byte("hello"),
		},
		{
			name:    "invalid padding",
			input:   []byte("hello\x01\x02"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Unpad(tt.input, 16)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unpad() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("Unpad() got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRandomBytes(t *testing.T) {
	tests := []struct {
		name        string
		size        int
		wantLen     int
		wantNonZero bool
	}{
		{
			name:        "random 16 bytes",
			size:        16,
			wantLen:     16,
			wantNonZero: true,
		},
		{
			name:    "zero bytes",
			size:    0,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RandomBytes(tt.size)
			if len(got) != tt.wantLen {
				t.Errorf("RandomBytes() got len %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantNonZero && tt.size > 0 {
				hasNonZero := false
				for _, b := range got {
					if b != 0 {
						hasNonZero = true
						break
					}
				}
				if !hasNonZero {
					t.Error("RandomBytes() expected at least one non-zero byte")
				}
			}
		})
	}
}
