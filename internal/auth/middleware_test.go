package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
)

func TestMiddleware_RequireToken(t *testing.T) {
	t.Parallel()

	const (
		headerCalled = "X-Handler-Called"
		mockToken    = "mock_token"
	)

	logging.SetupLogger("testing", "error", os.Stderr)

	tests := []struct {
		name             string
		authHeader       string
		signer           auth.Signer
		wantStatus       int
		wantHeaderCalled string
		wantUserID       string
	}{
		{
			name:       "valid token",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return map[string]any{
						"sub":     "1",
						"purpose": "session",
					}, nil
				},
			},
			wantStatus:       http.StatusOK,
			wantHeaderCalled: "true",
			wantUserID:       "1",
		},
		{
			name:       "no auth header",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty token",
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed auth header",
			authHeader: "Basic mock_token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing purpose claim",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return map[string]any{
						"sub": "1",
					}, nil
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "incorrect purpose claim",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return map[string]any{
						"sub":     "1",
						"purpose": "reset",
					}, nil
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing sub claim",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return map[string]any{
						"purpose": "reset",
					}, nil
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing claims",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return nil, nil
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "signer error",
			authHeader: "Bearer " + mockToken,
			signer: &auth.StubSigner{
				VerifyFunc: func(tokenString string) (map[string]any, error) {
					return nil, errors.New("verification failed")
				},
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotUserID string

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userID, err := auth.UserFromContext(r.Context())
				if err == nil {
					gotUserID = userID
				}
				w.Header().Set(headerCalled, "true")
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			mw := auth.RequireToken(tt.signer)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.wantStatus
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeaderCalled, wantHeaderCalled := rec.Header().Get(headerCalled), tt.wantHeaderCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}

			if gotUserID != tt.wantUserID {
				t.Errorf("gotUserID = %q, want: %q", gotUserID, tt.wantUserID)
			}
		})
	}
}
