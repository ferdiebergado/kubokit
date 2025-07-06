package middleware

import (
	"net/http"
)

const (
	HeaderAllowOrigin  = "Access-Control-Allow-Origin"
	HeaderAllowMethods = "Access-Control-Allow-Methods"
	HeaderAllowHeaders = "Access-Control-Allow-Headers"
	HeaderAllowCreds   = "Access-Control-Allow-Credentials"

	AllowedMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	AllowedHeaders = "Content-Type, Authorization"
	AllowedCreds   = "true"
)

func CORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == allowedOrigin {
				w.Header().Set(HeaderAllowOrigin, origin)
				w.Header().Set(HeaderAllowMethods, AllowedMethods)
				w.Header().Set(HeaderAllowHeaders, AllowedHeaders)
				w.Header().Set(HeaderAllowCreds, AllowedCreds)
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
