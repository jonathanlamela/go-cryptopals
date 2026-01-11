package hex

import (
	stdhex "encoding/hex"
	"strings"

	"github.com/jonathanlamela/go-cryptopals/pkg/base64"
	"github.com/jonathanlamela/go-cryptopals/pkg/errors"
)

type Hex struct{ Value string }

func FromString(s string) (Hex, error) {
	// validate hexdigits and even length
	if len(s)%2 != 0 {
		return Hex{}, errors.ErrInvalidHEXValue
	}

	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return Hex{}, errors.ErrInvalidHEXValue
		}
	}
	return Hex{Value: s}, nil
}

func FromHexString(s string) (Hex, error) { return Hex{Value: s}, nil }

func FromBytes(b []byte) (Hex, error) {
	dst := make([]byte, stdhex.EncodedLen(len(b)))
	stdhex.Encode(dst, b)
	return Hex{Value: string(dst)}, nil
}

func (h Hex) Len() int { return len(h.Value) }

func (h Hex) ToBytes() ([]byte, error) {
	s := strings.ToLower(h.Value)
	dst := make([]byte, stdhex.DecodedLen(len(s)))
	n, err := stdhex.Decode(dst, []byte(s))
	if err != nil {
		return nil, errors.ErrInvalidHEXToBytesConversion
	}
	return dst[:n], nil
}

func (h Hex) ToBase64() (base64.Base64, error) {
	b, err := h.ToBytes()
	if err != nil {
		return base64.Base64{}, errors.ErrInvalidHEXToBase64Conversion
	}
	return base64.FromBytes(b), nil
}

func (h Hex) String() string { return h.Value }
