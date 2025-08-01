package middleware

import (
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/config"
)

const (
	HeaderAllowOrigin  = "Access-Control-Allow-Origin"
	HeaderAllowMethods = "Access-Control-Allow-Methods"
	HeaderAllowHeaders = "Access-Control-Allow-Headers"
)

func CORS(cfg *config.CORS) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const sep = ","

			headers := map[string]string{
				HeaderAllowOrigin:  cfg.AllowedOrigin,
				HeaderAllowMethods: strings.Join(cfg.AllowedMethods, sep),
				HeaderAllowHeaders: strings.Join(cfg.AllowedHeaders, sep),
			}

			for k, v := range headers {
				w.Header().Set(k, v)
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
