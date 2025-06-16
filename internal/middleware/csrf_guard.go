package middleware

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

const (
	csrfCookieName  = "csrf_token"
	csrfHeaderName  = "X-CSRF-Token"
	csrfTokenLength = 32
)

func CSRFGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(csrfCookieName)
		// On safe methods, set token if missing
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			var token string
			if err != nil || cookie.Value == "" {
				b, randErr := security.GenerateRandomBytes(csrfTokenLength)
				if err != nil {
					web.RespondInternalServerError(w, randErr)
					return
				}
				token = base64.RawURLEncoding.EncodeToString(b)
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
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
			w.Header().Set(csrfHeaderName, token)
			next.ServeHTTP(w, r)
			return
		}

		// On unsafe methods, validate token
		if err != nil || cookie.Value == "" {
			web.RespondForbidden(w, errors.New("CSRF token missing"), message.InvalidInput, nil)
			return
		}
		sentToken := r.Header.Get(csrfHeaderName)
		if sentToken == "" {
			// Try to read from form data (for HTML forms)
			if err := r.ParseForm(); err != nil {
				web.RespondBadRequest(w, err, "Invalid form data.", nil)
				return
			}
			sentToken = r.FormValue(csrfCookieName)
		}
		if !security.ConstantTimeCompareStr(cookie.Value, sentToken) {
			web.RespondForbidden(w, errors.New("invalid CSRF token"), message.InvalidInput, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
