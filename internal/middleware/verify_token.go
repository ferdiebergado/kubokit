package middleware

import (
	"errors"
	"net/http"

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

			payload, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, ErrInvalidToken, message.InvalidUser, nil)
				return
			}

			ctx := user.NewContextWithUser(r.Context(), payload)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
