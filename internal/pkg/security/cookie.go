package security

import (
	"net/http"
	"time"
)

func HardenedCookie(name, val string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/",
		MaxAge:   time.Now().Add(maxAge).Second(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

type HardenedCookieBaker struct {
	name   string
	maxAge time.Duration
}

func (b *HardenedCookieBaker) Bake(val string) *http.Cookie {
	return HardenedCookie(b.name, val, b.maxAge)
}

func NewHardenedCookieBaker(name string, duration time.Duration) *HardenedCookieBaker {
	return &HardenedCookieBaker{
		name:   name,
		maxAge: duration,
	}
}
