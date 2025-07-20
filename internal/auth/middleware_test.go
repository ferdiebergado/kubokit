package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
)

func TestMiddleware_RequireToken(t *testing.T) {
	const headerCalled = "X-Handler-Called"

	type testCase struct {
		name, accessToken, headerCalled string
		signer                          jwt.Signer
		code                            int
	}

	testCases := []testCase{
		{
			name:        "With valid token",
			accessToken: "access_token",
			signer: &jwt.StubSigner{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "access_token", nil
				},
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{
						UserID: "1",
					}, nil
				},
			},
			code:         http.StatusOK,
			headerCalled: "true",
		},

		{
			name: "Without token",
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
			rec := httptest.NewRecorder()
			mw := auth.RequireToken(tc.signer)
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
