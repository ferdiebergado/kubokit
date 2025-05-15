package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/app/contract"
	contextx "github.com/ferdiebergado/kubokit/internal/context"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
)

func RequireAuth(signer contract.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil || tokenStr == "" {
				httpx.Fail(w, http.StatusUnauthorized, err, message.InvalidUser, nil)
				return
			}

			sub, err := signer.Verify(tokenStr)
			if err != nil {
				httpx.Fail(w, http.StatusUnauthorized, err, message.InvalidUser, nil)
				return
			}

			userCtx := contextx.NewContextWithUser(r.Context(), sub)
			r = r.WithContext(userCtx)
			next.ServeHTTP(w, r)
		})
	}
}

func extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("missing Bearer prefix")
	}
	return strings.TrimSpace(header[len(prefix):]), nil
}
