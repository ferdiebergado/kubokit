package middleware

import (
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func ContextGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.Context().Err(); err != nil {
			web.RespondRequestTimeout(w, err, "Request cancelled or timeout", nil)
			return
		}

		next.ServeHTTP(w, r)
	})
}
