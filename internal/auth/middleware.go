package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
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

			// TODO: check if fingerprint validation is needed
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

func RequireToken(fpCookieName string, signer jwt.Signer, hasher security.ShortHasher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Info("Verifying access token...")

			token, err := extractBearerToken(r.Header.Get("Authorization"))
			if err != nil || token == "" {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			fpCookie, err := r.Cookie(fpCookieName)
			if err != nil || fpCookie.Value == "" {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			fpBytes, err := base64.URLEncoding.DecodeString(fpCookie.Value)
			if err != nil {
				web.RespondInternalServerError(w, err)
				return
			}

			claims, err := signer.Verify(token)
			if err != nil {
				web.RespondUnauthorized(w, err, message.InvalidUser, nil)
				return
			}

			fpHashBytes, err := hex.DecodeString(claims.FingerprintHash)
			if err != nil {
				web.RespondInternalServerError(w, err)
				return
			}

			rehashedBytes, err := hasher.Hash(fpBytes)
			if err != nil {
				web.RespondInternalServerError(w, err)
				return
			}

			if subtle.ConstantTimeCompare(fpHashBytes, rehashedBytes) == 0 {
				web.RespondUnauthorized(w, errors.New("fingerprint hash mismatch"), message.InvalidUser, nil)
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
