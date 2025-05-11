package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	httpx "github.com/ferdiebergado/slim/internal/http"
	"github.com/ferdiebergado/slim/internal/message"
)

func CheckContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Checking Content-Type...")
		contentType := r.Header.Get(httpx.HeaderContentType)

		if contentType != httpx.MimeJSON {
			httpx.Fail(w, http.StatusNotAcceptable, fmt.Errorf("invalid content-type: %s", contentType), message.InvalidInput, nil)
			return
		}

		slog.Info("Content-Type is valid.")
		next.ServeHTTP(w, r)
	})
}
