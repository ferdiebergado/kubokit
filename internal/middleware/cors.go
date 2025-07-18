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
	AllowedHeaders = "Content-Type, Authorization, X-Client-Fingerprint"
)

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderAllowOrigin, "*")
		w.Header().Set(HeaderAllowMethods, AllowedMethods)
		w.Header().Set(HeaderAllowHeaders, AllowedHeaders)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
