package base64

import (
	"testing"

	"github.com/jonathanlamela/go-cryptopals/pkg/errors"
)

func TestFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid base64",
			input: "SGVsbG8gV29ybGQ=",
			want:  "SGVsbG8gV29ybGQ=",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromString(tt.input)
			if got.Value != tt.want {
				t.Errorf("FromString() got = %v, want %v", got.Value, tt.want)
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "hello world to base64",
			input: []byte("Hello World"),
			want:  "SGVsbG8gV29ybGQ=",
		},
		{
			name:  "empty bytes",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{65},
			want:  "QQ==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromBytes(tt.input)
			if got.Value != tt.want {
				t.Errorf("FromBytes() got = %v, want %v", got.Value, tt.want)
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
			name:  "hello world from base64",
			input: "SGVsbG8gV29ybGQ=",
			want:  []byte("Hello World"),
		},
		{
			name:  "single char",
			input: "QQ==",
			want:  []byte{65},
		},
		{
			name:    "invalid base64",
			input:   "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Base64{Value: tt.input}
			got, err := b.ToBytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("ToBytes() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "base64 string",
			input: "SGVsbG8=",
			want:  "SGVsbG8=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Base64{Value: tt.input}
			if got := b.String(); got != tt.want {
				t.Errorf("String() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	b := Base64{Value: "!!!invalid!!!"}
	_, err := b.ToBytes()
	if err != errors.ErrInvalidBase64ToBytes {
		t.Errorf("Expected ErrInvalidBase64ToBytes, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "round trip hello",
			input: []byte("Hello"),
		},
		{
			name:  "round trip empty",
			input: []byte{},
		},
		{
			name:  "round trip binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := FromBytes(tt.input)
			decoded, err := b64.ToBytes()
			if err != nil {
				t.Fatalf("ToBytes() error = %v", err)
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}
