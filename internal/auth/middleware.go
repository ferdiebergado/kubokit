package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

var ErrInvalidToken = errors.New("invalid token")

// VerifyToken verifies if the token in the url query string is valid.
func VerifyToken(signer jwt.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				web.RespondUnauthorized(w, ErrInvalidToken, message.InvalidUser, nil)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, ErrInvalidToken, message.InvalidUser, nil)
				return
			}

			ctx := user.NewContextWithUser(r.Context(), claims.UserID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func RequireToken(signer jwt.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Verifying access token...")

			token, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil || token == "" {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			ctx := user.NewContextWithUser(r.Context(), claims.UserID)
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
