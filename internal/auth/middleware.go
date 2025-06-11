package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func RequireToken(signer jwt.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil || tokenStr == "" {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			userID, err := signer.Verify(tokenStr)
			if err != nil {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			ctx := user.NewContextWithUser(r.Context(), userID)
			r = r.WithContext(ctx)
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
