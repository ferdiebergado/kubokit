package auth_test

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
)

func TestMiddleware_RequireToken(t *testing.T) {
	const defaultCookieName = "__Secure-fp"

	type testCase struct {
		name, token string
		fingerprint []byte
		cookie      *http.Cookie
		signer      jwt.Signer
		hasher      security.ShortHasher
		code        int
	}

	testCases := []testCase{
		{
			name:        "With valid token and fingerprint cookie",
			token:       "access_token",
			fingerprint: []byte("test_fp"),
			cookie: &http.Cookie{
				Name:     defaultCookieName,
				MaxAge:   time.Now().Add(15 * time.Minute).Second(),
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				Value:    base64.URLEncoding.EncodeToString([]byte("test_fp")),
			},
			signer: &jwt.StubSigner{
				SignFunc: func(subject, fingerprint string, audience []string, duration time.Duration) (string, error) {
					return "access_token", nil
				},
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{
						UserID:          "1",
						FingerprintHash: hex.EncodeToString([]byte("test_fp")),
					}, nil
				},
			},
			hasher: security.HasherFunc(func(b []byte) ([]byte, error) {
				return []byte("test_fp"), nil
			}),
			code: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()

			mw := auth.RequireToken(defaultCookieName, tc.signer, tc.hasher)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, http.StatusOK
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}
		})
	}
}
