package base64

import (
	stdb64 "encoding/base64"
	"github.com/jonathanlamela/go-cryptopals/pkg/errors"
)

type Base64 struct{ Value string }

func FromString(s string) Base64 { return Base64{Value: s} }
func FromBytes(b []byte) Base64  { return Base64{Value: stdb64.StdEncoding.EncodeToString(b)} }

func (b Base64) ToBytes() ([]byte, error) {
	decoded, err := stdb64.StdEncoding.DecodeString(b.Value)
	if err != nil {
		return nil, errors.ErrInvalidBase64ToBytes
	}
	return decoded, nil
}

func (b Base64) String() string { return b.Value }
