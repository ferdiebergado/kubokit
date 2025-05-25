package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/app/contract"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
)

func ValidateInput[T any](validator contract.Validator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Validating input...")
			params, err := httpx.ParamsFromContext[T](r.Context())

			if err != nil {
				httpx.Fail(w, http.StatusBadRequest, err, message.InvalidInput, nil)
				return
			}

			if err := validator.ValidateStruct(params); err != nil {
				httpx.Fail(w, http.StatusBadRequest, errors.New("invalid input"), message.InvalidInput, err)
				return
			}

			slog.Info("Input is valid.")
			next.ServeHTTP(w, r)
		})
	}
}
