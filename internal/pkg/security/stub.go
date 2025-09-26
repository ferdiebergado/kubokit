package security

import (
	"errors"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

type StubCSRFCookieBaker struct {
	BakeFunc func() (*http.Cookie, error)
}

func (s *StubCSRFCookieBaker) Bake() (*http.Cookie, error) {
	if s.BakeFunc == nil {
		panic("Bake not implemented by stub")
	}
	return s.BakeFunc()
}

var _ web.Baker = &StubCSRFCookieBaker{}

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
