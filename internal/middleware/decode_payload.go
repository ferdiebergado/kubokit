package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func DecodePayload[T any](bodySize int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Decoding json payload...")
			r.Body = http.MaxBytesReader(w, r.Body, bodySize)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			var decoded T
			if err := decoder.Decode(&decoded); err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					web.RespondRequestEntityTooLarge(w, err, message.InvalidInput, nil)
					return
				}

				const fieldErr = "json: unknown field "
				errMsg := err.Error()
				if fieldName, ok := strings.CutPrefix(errMsg, fieldErr); ok {
					details := map[string]string{"field": fieldName}
					web.RespondUnprocessableEntity(w, err, "Unknown field in payload.", details)
					return
				}

				web.RespondBadRequest(w, err, message.InvalidInput, nil)
				return
			}

			if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				web.RespondBadRequest(w, err, message.InvalidInput, nil)
				return
			}

			ctx := web.NewContextWithParams(r.Context(), decoded)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
