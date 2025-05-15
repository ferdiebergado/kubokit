package middleware

import "net/http"

func InjectWriter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := NewSafeResponseWriter(r.Context(), w)
		next.ServeHTTP(writer, r)
	})
}
