package middleware

import (
	"errors"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func CSRFGuard(cfg *config.CSRF) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil || cookie.Value == "" {
				web.RespondUnauthorized(w, errors.New("missing csrf cookie"), message.InvalidUser, nil)
				return
			}

			cookieToken := cookie.Value
			headerToken := r.Header.Get(cfg.HeaderName)
			if headerToken != cookieToken {
				web.RespondUnauthorized(w, errors.New("invalid csrf token"), message.InvalidUser, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
