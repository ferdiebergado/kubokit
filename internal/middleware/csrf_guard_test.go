package middleware_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
)

func TestCSRFGuard(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name             string
		method           string
		code             int
		token            string
		randomizerFunc   security.Randomizer
		setReqCookieFunc func(*http.Request)
		checkCookie      bool
	}{
		{
			"get request without csrf token cookie",
			http.MethodGet,
			http.StatusOK,
			"test_token",
			func(_ uint32) ([]byte, error) { return []byte("test_token"), nil },
			nil,
			true,
		},
		{
			"post request with csrf token cookie",
			http.MethodPost,
			http.StatusOK,
			"",
			func(_ uint32) ([]byte, error) { return nil, nil },
			func(r *http.Request) {
				token := base64.RawURLEncoding.EncodeToString([]byte("test_token"))
				csrfCookie := &http.Cookie{
					Name:     middleware.CookieCSRF,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					Expires:  time.Now().Add(24 * time.Hour),
				}
				r.AddCookie(csrfCookie)
				r.Header.Set(middleware.HeaderCSRF, token)
			},
			false,
		},
		{
			"post request without csrf token cookie",
			http.MethodPost,
			http.StatusForbidden,
			"test_token",
			func(_ uint32) ([]byte, error) { return nil, nil },
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", http.NoBody)
			rec := httptest.NewRecorder()
			if tt.setReqCookieFunc != nil {
				tt.setReqCookieFunc(req)
			}

			mw := middleware.CSRFGuard(tt.randomizerFunc)(handler)
			mw.ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			if tt.checkCookie {
				resp := rec.Result()
				defer resp.Body.Close()

				cookies := resp.Cookies()

				var csrfCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == middleware.CookieCSRF {
						csrfCookie = cookie
						break
					}
				}

				gotCookie := csrfCookie.Value
				wantCookie := base64.RawURLEncoding.EncodeToString([]byte(tt.token))
				if gotCookie != wantCookie {
					t.Errorf("cookie = %q, want: %q", gotCookie, wantCookie)
				}
			}
		})
	}
}
