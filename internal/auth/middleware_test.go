package auth_test

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
)

func TestMiddleware_RequireToken(t *testing.T) {
	const headerCalled = "X-Handler-Called"

	type testCase struct {
		name, accessToken, headerCalled string
		fingerprint                     []byte
		signer                          jwt.Signer
		hasher                          security.ShortHasher
		code                            int
		fpCookie                        *http.Cookie
	}

	testCases := []testCase{
		{
			name:        "With valid token and fingerprint",
			accessToken: "access_token",
			fingerprint: []byte("test_fp"),
			fpCookie:    security.HardenedCookie("access_fp", base64.URLEncoding.EncodeToString([]byte("test_fp")), defaultDuration),
			signer: &jwt.StubSigner{
				SignFunc: func(subject, fingerprint string, audience []string, duration time.Duration) (string, error) {
					return "access_token", nil
				},
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{
						UserID:          "1",
						FingerprintHash: hex.EncodeToString([]byte("test_fp_hash")),
					}, nil
				},
			},
			hasher: &security.StubSHA256Hasher{
				HashFunc: func(_ string) ([]byte, error) {
					return []byte("test_fp_hash"), nil
				},
			},
			code:         http.StatusOK,
			headerCalled: "true",
		},
		{
			name:        "With valid token but without fingerprint",
			accessToken: "access_token",
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{
						UserID:          "1",
						FingerprintHash: hex.EncodeToString([]byte("test_fp_hash")),
					}, nil
				},
			},
			code: http.StatusUnauthorized,
		},
		{
			name: "Without token and fingerprint",
			code: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(headerCalled, "true")
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tc.accessToken)
			if tc.fpCookie != nil {
				req.AddCookie(tc.fpCookie)
			}
			rec := httptest.NewRecorder()

			cookieCfg := &config.Cookie{
				Refresh:            "refresh_token",
				AccessFingerprint:  "access_fp",
				RefreshFingerprint: "refresh_fp",
			}
			mw := auth.RequireToken(cookieCfg, tc.signer, tc.hasher)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeaderCalled, wantHeaderCalled := rec.Header().Get(headerCalled), tc.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}
		})
	}
}
