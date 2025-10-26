package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
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

			ctx := ContextWithUser(r.Context(), claims.UserID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func RequireToken(signer jwt.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Verifying access token...")

			token, err := security.ExtractBearerToken(r)
			if err != nil || token == "" {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			ctx := ContextWithUser(r.Context(), claims.UserID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
