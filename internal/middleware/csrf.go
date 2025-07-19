package middleware

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func CSRFGuard(cfg *config.CSRF, hasher security.ShortHasher, baker web.Baker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.CookieName)

			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				var token string
				if err != nil || cookie.Value == "" {
					csrfToken, csrfErr := csrf(cfg.TokenLen, hasher)
					if csrfErr != nil {
						web.RespondInternalServerError(w, csrfErr)
						return
					}
					token = csrfToken
					csrfCookie := baker.Bake(token)
					csrfCookie.HttpOnly = false
					http.SetCookie(w, csrfCookie)
				} else {
					token = cookie.Value
				}
				w.Header().Set(cfg.HeaderName, token)
				next.ServeHTTP(w, r)
				return
			}

			if err != nil || cookie.Value == "" {
				web.RespondForbidden(w, err, message.InvalidUser, nil)
				return
			}

			csrfToken := cookie.Value
			csrfTokenHeader := r.Header.Get(cfg.HeaderName)
			if subtle.ConstantTimeCompare([]byte(csrfToken), []byte(csrfTokenHeader)) == 0 {
				web.RespondForbidden(w, errors.New("csrf token from cookie and header did not match"), message.InvalidUser, nil)
				return
			}

			token, sigBytes, err := splitToken(csrfToken)
			if err != nil {
				web.RespondForbidden(w, err, message.InvalidUser, nil)
				return
			}

			expectedSig, err := hasher.Hash(token)
			if err != nil {
				web.RespondForbidden(w, err, message.InvalidUser, nil)
				return
			}

			if ok := hmac.Equal(sigBytes, expectedSig); !ok {
				web.RespondForbidden(w, fmt.Errorf("hmac compare: %w", errors.New("mac mismatch")), message.InvalidUser, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func csrf(length uint32, hasher security.ShortHasher) (string, error) {
	token, err := security.GenerateRandomBytesURLEncoded(length)
	if err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	signature, err := hasher.Hash(token)
	if err != nil {
		return "", fmt.Errorf("hash csrf token: %w", err)
	}

	csrfToken := token + ":" + base64.RawURLEncoding.EncodeToString(signature)

	return csrfToken, nil
}

func splitToken(csrfToken string) (token string, sigBytes []byte, err error) {
	parts := strings.SplitN(csrfToken, ":", 2)
	if len(parts) != 2 {
		return "", nil, errors.New("invalid csrf token")
	}

	token, sig := parts[0], parts[1]
	sigBytes, err = base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", nil, fmt.Errorf("base64 decode csrf token signature: %w", err)
	}
	return token, sigBytes, nil
}
