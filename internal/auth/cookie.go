package auth

import (
	"net/http"
	"time"
)

func NewFingerprintCookie(fingerprint string, duration time.Duration) *http.Cookie {
	cookie := &http.Cookie{
		Name:     "__Secure-fp",
		Value:    fingerprint,
		Path:     "/",
		MaxAge:   time.Now().Add(duration).Second(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return cookie
}
