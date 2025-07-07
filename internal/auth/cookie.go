package auth

import (
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

var _ web.Baker = &FingerprintCookieBaker{}

type FingerprintCookieBaker struct {
	CookieName     string
	CookieDuration time.Duration
}

func (f *FingerprintCookieBaker) Bake(fingerprint string) *http.Cookie {
	cookie := &http.Cookie{
		Name:     f.CookieName,
		Value:    fingerprint,
		Path:     "/",
		MaxAge:   time.Now().Add(f.CookieDuration).Second(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return cookie
}

func NewFingerprintCookieBaker(name string, duration time.Duration) *FingerprintCookieBaker {
	return &FingerprintCookieBaker{
		CookieName:     name,
		CookieDuration: duration,
	}
}
