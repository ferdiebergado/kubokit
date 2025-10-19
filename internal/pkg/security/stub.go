package security

import (
	"errors"
)

type StubSHA256Hasher struct {
	HashFunc func(string) ([]byte, error)
}

func (h *StubSHA256Hasher) Hash(s string) ([]byte, error) {
	if h.HashFunc == nil {
		return nil, errors.New("Hash not implemented by stub")
	}
	return h.HashFunc(s)
}

var _ ShortHasher = &StubSHA256Hasher{}
