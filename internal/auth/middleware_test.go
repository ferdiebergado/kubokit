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
	type testCase struct {
		name, token, fpHeader string
		fingerprint           []byte
		signer                jwt.Signer
		hasher                security.ShortHasher
		code                  int
	}

	testCases := []testCase{
		{
			name:        "With valid token and fingerprint",
			token:       "access_token",
			fingerprint: []byte("test_fp"),
			fpHeader:    base64.URLEncoding.EncodeToString([]byte("test_fp")),
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
			req.Header.Set(auth.HeaderFingerprint, tc.fpHeader)
			rec := httptest.NewRecorder()

			mw := auth.RequireToken(tc.signer, tc.hasher)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, http.StatusOK
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}
		})
	}
}
