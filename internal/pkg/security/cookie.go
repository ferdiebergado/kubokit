package security

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

type CSRFCookieBaker struct {
	name   string
	length uint32
	maxAge int
}

func (b *CSRFCookieBaker) Bake() (*http.Cookie, error) {
	token, err := GenerateRandomBytesURLEncoded(b.length)
	if err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}

	cookie := &http.Cookie{
		Name:     b.name,
		Value:    token,
		Path:     "/auth/refresh",
		MaxAge:   b.maxAge,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteNoneMode,
	}

	return cookie, nil
}

func NewCSRFCookieBaker(name string, length uint32, maxAge time.Duration) *CSRFCookieBaker {
	return &CSRFCookieBaker{
		name:   name,
		length: length,
		maxAge: time.Now().Add(maxAge).Second(),
	}
}

var _ web.Baker = &CSRFCookieBaker{}
