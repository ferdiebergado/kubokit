package middleware_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
)

func TestValidateInput(t *testing.T) {
	t.Parallel()

	const (
		headerCalled = "X-Handler-Called"
		testName     = "fely"
		testEmail    = "fely@example.com"
		emailErr     = "email must be a valid email address"
	)

	type profile struct {
		Name  string `json:"name" validate:"required"`
		Email string `json:"email" validate:"required,email"`
	}

	tests := []struct {
		name               string
		code               int
		payload            any
		valFunc            func(any) map[string]string
		body, headerCalled string
	}{
		{"Valid input", http.StatusOK, profile{testName, testEmail}, func(_ any) map[string]string { return nil },
			`{"name":"fely","email":"fely@example.com"}`, "true"},
		{"Invalid input", http.StatusUnprocessableEntity, profile{testName, "fely@example"}, func(_ any) map[string]string {
			return map[string]string{"email": emailErr}
		}, `{"message":"Invalid input.","errors":{"email":"email must be a valid email address"}}`, ""},
		{"Invalid type", http.StatusBadRequest, struct{}{}, func(_ any) map[string]string {
			return nil
		}, `{"message":"Invalid input."}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, err := web.ParamsFromContext[profile](r.Context())
				if err != nil {
					const code = http.StatusBadRequest
					http.Error(w, http.StatusText(code), code)
					return
				}
				w.Header().Set(web.HeaderContentType, web.MimeJSON)
				w.Header().Set(headerCalled, "true")
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(&p); err != nil {
					slog.Error("failed to decode json", "reason", err)
				}
			})

			ctx := web.NewContextWithParams(context.Background(), tc.payload)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", http.NoBody)
			rec := httptest.NewRecorder()
			valdtr := &validation.StubValidator{
				ValidateStructFunc: tc.valFunc,
			}
			mw := middleware.ValidateInput[profile](valdtr)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeader, wantHeader := rec.Header().Get(web.HeaderContentType), web.MimeJSON
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", web.HeaderContentType, gotHeader, wantHeader)
			}

			gotHeaderCalled, wantHeaderCalled := rec.Header().Get(headerCalled), tc.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}

			gotBody, wantBody := strings.TrimSuffix(rec.Body.String(), "\n"), tc.body
			if gotBody != wantBody {
				t.Errorf("rec.Body.String() = %q, want: %q", gotBody, wantBody)
			}
		})
	}
}
