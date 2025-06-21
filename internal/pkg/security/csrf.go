package security

import (
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/config"
)

type CSRFCookieBaker struct {
	name   string
	length uint32
}

func (c *CSRFCookieBaker) Bake() (*http.Cookie, error) {
	token, err := GenerateRandomBytesURLEncoded(c.length)
	if err != nil {
		return nil, err
	}

	csrfCookie := NewSecureCookie(c.name, token)
	return csrfCookie, nil
}

func NewCSRFCookieBaker(cfg *config.CSRF) *CSRFCookieBaker {
	return &CSRFCookieBaker{
		name:   cfg.CookieName,
		length: cfg.TokenLength,
	}
}
