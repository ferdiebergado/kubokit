package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	contextx "github.com/ferdiebergado/slim/internal/context"
	httpx "github.com/ferdiebergado/slim/internal/http"
)

func ParsePayload[T any]() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Checking content-type...")
			contentType := r.Header.Get(httpx.HeaderContentType)

			if contentType != httpx.MimeJSON {
				httpx.Fail(w, http.StatusNotAcceptable, fmt.Errorf("Invalid content-type: %s", contentType), "Invalid input.")
				return
			}

			slog.Info("Decoding json payload...")
			var decoded T
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&decoded); err != nil {
				httpx.Fail(w, http.StatusBadRequest, err, "Invalid input.")

				return
			}

			slog.Info("Payload decoded", slog.Any("payload", &decoded))

			ctx := contextx.NewContextWithParams(r.Context(), decoded)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
