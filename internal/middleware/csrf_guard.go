package middleware

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

const (
	CookieCSRF      = "csrf_token"
	HeaderCSRF      = "X-CSRF-Token"
	csrfTokenLength = 32
)

func CSRFGuard(randomizer security.Randomizer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(CookieCSRF)
			// On safe methods, set token if missing
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				var token string
				if err != nil || cookie.Value == "" {
					b, randErr := randomizer.GenerateRandomBytes(csrfTokenLength)
					if randErr != nil {
						web.RespondInternalServerError(w, randErr)
						return
					}
					token = base64.RawURLEncoding.EncodeToString(b)
					http.SetCookie(w, &http.Cookie{
						Name:     CookieCSRF,
						Value:    token,
						Path:     "/",
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteStrictMode,
						Expires:  time.Now().Add(24 * time.Hour),
					})
				} else {
					token = cookie.Value
				}
				// Optionally expose the token to JS clients via header
				w.Header().Set(HeaderCSRF, token)
				next.ServeHTTP(w, r)
				return
			}

			// On unsafe methods, validate token
			if err != nil || cookie.Value == "" {
				web.RespondForbidden(w, errors.New("CSRF token missing"), message.InvalidInput, nil)
				return
			}
			sentToken := r.Header.Get(HeaderCSRF)
			if sentToken == "" {
				// Try to read from form data (for HTML forms)
				if err := r.ParseForm(); err != nil {
					web.RespondBadRequest(w, err, "Invalid form data.", nil)
					return
				}
				sentToken = r.FormValue(CookieCSRF)
			}
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sentToken)) == 0 {
				web.RespondForbidden(w, errors.New("invalid CSRF token"), message.InvalidInput, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
