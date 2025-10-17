package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/config"
)

const (
	HeaderAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAllowCredentials = "Access-Control-Allow-Credentials"
)

func CORS(cfg *config.CORS) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if os.Getenv("ENV") != "development" {
				next.ServeHTTP(w, r)
				return
			}

			const sep = ","

			headers := map[string]string{
				HeaderAllowOrigin:      cfg.AllowedOrigin,
				HeaderAllowMethods:     strings.Join(cfg.AllowedMethods, sep),
				HeaderAllowHeaders:     strings.Join(cfg.AllowedHeaders, sep),
				HeaderAllowCredentials: cfg.AllowCredentials,
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
