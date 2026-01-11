package hex

import (
	"testing"

	"github.com/jonathanlamela/go-cryptopals/pkg/errors"
)

func TestFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid hex string",
			input:   "48656c6c6f",
			wantErr: false,
		},
		{
			name:    "valid hex with uppercase",
			input:   "48656C6C6F",
			wantErr: false,
		},
		{
			name:    "odd length hex",
			input:   "48656c6c6",
			wantErr: true,
		},
		{
			name:    "invalid hex characters",
			input:   "48656c6c6g",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromString() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.S != tt.input {
					t.Errorf("FromString() got = %v, want %v", got.S, tt.input)
				}
			}
		})
	}
}

func TestToBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "hello to bytes",
			input: "48656c6c6f",
			want:  []byte("Hello"),
		},
		{
			name:  "uppercase hex",
			input: "48656C6C6F",
			want:  []byte("Hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := FromString(tt.input)
			if err != nil {
				t.Fatalf("FromString() error = %v", err)
			}
			got, err := h.ToBytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("ToBytes() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "hello bytes to hex",
			input: []byte("hello"),
		},
		{
			name:  "empty bytes",
			input: []byte{},
		},
		{
			name:  "single byte",
			input: []byte{0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := FromBytes(tt.input)
			// Round-trip test: bytes -> hex -> bytes should be original
			decoded, _ := got.ToBytes()
			if string(decoded) != string(tt.input) {
				t.Errorf("Round-trip failed: input %v, got %v", tt.input, decoded)
			}
		})
	}
}

func TestLen(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "hex length",
			input: "48656c6c6f",
			want:  10,
		},
		{
			name:  "empty hex",
			input: "",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Hex{S: tt.input}
			if got := h.Len(); got != tt.want {
				t.Errorf("Len() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToBase64(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "hex to base64",
			input: "48656c6c6f",
			want:  "SGVsbG8=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := FromString(tt.input)
			got, _ := h.ToBase64()
			if got.String() != tt.want {
				t.Errorf("ToBase64() got = %v, want %v", got.String(), tt.want)
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	_, err := FromString("48656c6c6")
	if err != errors.ErrInvalidHEXValue {
		t.Errorf("Expected ErrInvalidHEXValue, got %v", err)
	}

	_, err = FromString("48656c6c6g")
	if err != errors.ErrInvalidHEXValue {
		t.Errorf("Expected ErrInvalidHEXValue, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "round trip hello",
			input: []byte("hello"),
		},
		{
			name:  "round trip empty",
			input: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := FromBytes(tt.input)
			decoded, _ := h.ToBytes()
			if string(decoded) != string(tt.input) {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}
