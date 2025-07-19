package middleware

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)

		writer, ok := w.(*SafeResponseWriter)
		if !ok {
			web.RespondInternalServerError(w, errors.New("responseWriter is not a SafeResponseWriter"))
			return
		}

		duration := time.Since(start)
		slog.Info("incoming request",
			"user_agent", r.UserAgent(),
			"origin", r.Header.Get("Origin"),
			"ip", getIPAddress(r),
			"method", r.Method,
			"url", r.URL.String(),
			"proto", r.Proto,
			slog.Int("status_code", writer.Status()),
			slog.Int("bytes", writer.BytesWritten()),
			"duration", duration,
		)
	})
}

// getIPAddress extracts the client's IP address from the request.
func getIPAddress(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	if forwardedFor := r.Header.Values("X-Forwarded-For"); len(forwardedFor) > 0 {
		firstIP := forwardedFor[0]
		ips := strings.Split(firstIP, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
