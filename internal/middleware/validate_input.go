package middleware

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	contextx "github.com/ferdiebergado/slim/internal/context"
	"github.com/ferdiebergado/slim/internal/contract"
	httpx "github.com/ferdiebergado/slim/internal/http"
	"github.com/ferdiebergado/slim/internal/message"
)

func ValidateInput[T any](validator contract.Validator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Validating input...")
			ctxVal, params, ok := contextx.ParamsFromContext[T](r.Context())

			if !ok {
				var t T
				err := fmt.Errorf("cannot type assert context value %v to %T", ctxVal, t)
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
