package security

import (
	"errors"
	"net/http"
)

type StubBaker struct {
	BakeFunc func() (*http.Cookie, error)
}

func (s *StubBaker) Bake() (*http.Cookie, error) {
	if s.BakeFunc == nil {
		return nil, errors.New("Bake not implemented by stub")
	}
	return s.BakeFunc()
}
