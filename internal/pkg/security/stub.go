package security

import (
	"errors"
	"net/http"
)

type StubHardenedCookieBaker struct {
	BakeFunc func(string) *http.Cookie
}

func (s *StubHardenedCookieBaker) Bake(val string) *http.Cookie {
	if s.BakeFunc == nil {
		panic("Bake not implemented by stub")
	}
	return s.BakeFunc(val)
}

type StubSHA256Hasher struct {
	HashFunc func(string) ([]byte, error)
}

func (h *StubSHA256Hasher) Hash(s string) ([]byte, error) {
	if h.HashFunc == nil {
		return nil, errors.New("Hash not implemented by stub")
	}
	return h.HashFunc(s)
}
