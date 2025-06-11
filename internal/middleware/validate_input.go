package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
)

func ValidateInput[T any](validator validation.Validator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Validating input...")
			params, err := web.ParamsFromContext[T](r.Context())

			if err != nil {
				web.Fail(w, http.StatusBadRequest, err, message.InvalidInput, nil)
				return
			}

			if err := validator.ValidateStruct(params); err != nil {
				web.Fail(w, http.StatusBadRequest, errors.New("invalid input"), message.InvalidInput, err)
				return
			}

			slog.Info("Input is valid.")
			next.ServeHTTP(w, r)
		})
	}
}
