package security

import (
	"errors"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

var _ web.Baker = &StubBaker{}

type StubBaker struct {
	BakeFunc  func() (*http.Cookie, error)
	CheckFunc func(*http.Cookie) error
}

func (s *StubBaker) Bake() (*http.Cookie, error) {
	if s.BakeFunc == nil {
		return nil, errors.New("Bake not implemented by stub")
	}
	return s.BakeFunc()
}

func (s *StubBaker) Check(cookie *http.Cookie) error {
	if s.CheckFunc == nil {
		return errors.New("Verify is not implemented by stub")
	}
	return s.CheckFunc(cookie)
}
