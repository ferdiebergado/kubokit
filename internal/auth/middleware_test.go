package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/auth"
)

func TestMiddleware_RequireToken(t *testing.T) {
	t.Parallel()

	const headerCalled = "X-Handler-Called"

	tests := []struct {
		name, accessToken, headerCalled string
		signer                          auth.Signer
		code                            int
	}{
		{
			name:        "With valid token",
			accessToken: "access_token",
			signer: &auth.StubSigner{
				SignFunc: func(claims map[string]any) (string, error) {
					return "access_token", nil
				},
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return map[string]any{
						"sub": "1",
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(headerCalled, "true")
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.accessToken)
			rec := httptest.NewRecorder()
			mw := auth.RequireToken(tt.signer)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeaderCalled, wantHeaderCalled := rec.Header().Get(headerCalled), tt.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}
		})
	}
}
