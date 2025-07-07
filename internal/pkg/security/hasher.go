package security

import (
	"crypto/sha256"
	"fmt"
)

type ShortHasher interface {
	Hash([]byte) ([]byte, error)
}

type HasherFunc func([]byte) ([]byte, error)

func (f HasherFunc) Hash(data []byte) ([]byte, error) {
	return f(data)
}

var SHA256Hasher = HasherFunc(func(b []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(b); err != nil {
		return nil, fmt.Errorf("hasher write data: %w", err)
	}
	return h.Sum(nil), nil
})
