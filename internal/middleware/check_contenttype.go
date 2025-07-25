package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func CheckContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Checking Content-Type...")
		contentType := r.Header.Get(web.HeaderContentType)

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if contentType != web.MimeJSON {
				web.RespondUnsupportedMediaType(w, fmt.Errorf("unsupported content-type: %s", contentType), message.InvalidInput, nil)
				return
			}
		}

		slog.Info("Content-Type is valid.")
		next.ServeHTTP(w, r)
	})
}
