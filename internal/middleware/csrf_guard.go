package middleware

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func CSRFGuard(cfg *config.CSRF, csrfBaker web.Baker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.CookieName)
			// On safe methods, set token if missing
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				var token string
				if err != nil || cookie.Value == "" {
					csrfCookie, randErr := csrfBaker.Bake()
					if randErr != nil {
						web.RespondInternalServerError(w, randErr)
						return
					}
					http.SetCookie(w, csrfCookie)
					token = csrfCookie.Value
				} else {
					token = cookie.Value
				}
				// Optionally expose the token to JS clients via header
				w.Header().Set(cfg.HeaderName, token)
				next.ServeHTTP(w, r)
				return
			}

			// On unsafe methods, validate token
			if err != nil || cookie.Value == "" {
				web.RespondForbidden(w, errors.New("CSRF token missing"), message.InvalidInput, nil)
				return
			}
			sentToken := r.Header.Get(cfg.HeaderName)
			if sentToken == "" {
				// Try to read from form data (for HTML forms)
				if err := r.ParseForm(); err != nil {
					web.RespondBadRequest(w, err, "Invalid form data.", nil)
					return
				}
				sentToken = r.FormValue(cfg.CookieName)
			}
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sentToken)) == 0 {
				web.RespondForbidden(w, errors.New("invalid CSRF token"), message.InvalidInput, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
