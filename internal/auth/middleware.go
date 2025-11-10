package auth

import (
	"log/slog"
	"net/http"

	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

// VerifyToken verifies if the token in the url query string is valid.
func VerifyToken(signer Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				web.RespondUnauthorized(w, ErrInvalidToken, MsgInvalidUser, nil)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, ErrInvalidToken, MsgInvalidUser, nil)
				return
			}

			userID, ok := claims["sub"].(string)
			if !ok {
				web.RespondUnauthorized(w, ErrInvalidToken, MsgInvalidUser, nil)
				return
			}

			ctx := ContextWithUser(r.Context(), userID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func RequireToken(signer Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Verifying access token...")

			token, err := security.ExtractBearerToken(r)
			if err != nil || token == "" {
				web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
				return
			}

			userID, ok := claims["sub"].(string)
			if !ok {
				web.RespondUnauthorized(w, ErrInvalidToken, MsgInvalidUser, nil)
				return
			}

			ctx := ContextWithUser(r.Context(), userID)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
