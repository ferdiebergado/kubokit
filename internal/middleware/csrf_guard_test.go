package middleware_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func TestCSRFGuard(t *testing.T) {
	t.Parallel()

	const headerCalled = "X-Header-Called"

	cfg := &config.CSRF{
		CookieName:  "csrf_token",
		HeaderName:  "X-CSRF-Token",
		TokenLength: 32,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerCalled, "true")
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		method         string
		code           int
		csrfHeader     string
		stubBaker      web.Baker
		cookie         *http.Cookie
		prevCookie     *http.Cookie
		prevCSRFHeader string
		headerCalled   string
	}{
		{
			"GET request without csrf header and cookie",
			http.MethodGet,
			http.StatusOK,
			base64.RawURLEncoding.EncodeToString([]byte("test_token")),
			&security.StubBaker{BakeFunc: func() (*http.Cookie, error) {
				return &http.Cookie{
					Name:     cfg.CookieName,
					Value:    base64.RawURLEncoding.EncodeToString([]byte("test_token")),
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					Expires:  time.Now().Add(24 * time.Hour),
				}, nil
			}},
			&http.Cookie{
				Name:     cfg.CookieName,
				Value:    base64.RawURLEncoding.EncodeToString([]byte("test_token")),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Expires:  time.Now().Add(24 * time.Hour),
			},
			nil,
			"",
			"true",
		},
		{
			"POST request with csrf header and cookie",
			http.MethodPost,
			http.StatusOK,
			"",
			&security.StubBaker{BakeFunc: func() (*http.Cookie, error) { return &http.Cookie{}, nil }},
			nil,
			&http.Cookie{
				Name:     cfg.CookieName,
				Value:    base64.RawURLEncoding.EncodeToString([]byte("test_token")),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				Expires:  time.Now().Add(24 * time.Hour),
			},
			base64.RawURLEncoding.EncodeToString([]byte("test_token")),
			"true",
		},
		{
			"POST request without csrf header and cookie",
			http.MethodPost,
			http.StatusForbidden,
			"",
			&security.StubBaker{BakeFunc: func() (*http.Cookie, error) { return &http.Cookie{}, nil }},
			nil,
			nil,
			"",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, "/", http.NoBody)
			rec := httptest.NewRecorder()
			if tt.prevCSRFHeader != "" {
				req.Header.Set(cfg.HeaderName, tt.prevCSRFHeader)
			}
			if tt.prevCookie != nil {
				req.AddCookie(tt.prevCookie)
			}

			mw := middleware.CSRFGuard(cfg, tt.stubBaker)(handler)
			mw.ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeader := rec.Header().Get(cfg.HeaderName)
			wantHeader := tt.csrfHeader
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", cfg.HeaderName, gotHeader, wantHeader)
			}

			gotHeaderCalled := rec.Header().Get(headerCalled)
			wantHeaderCalled := tt.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}

			if tt.cookie != nil {
				resp := rec.Result()
				defer resp.Body.Close()

				cookies := resp.Cookies()
				gotLen, wantLen := len(cookies), 1
				if gotLen != wantLen {
					t.Fatal("no cookie was set")
				}
				cookie := cookies[0]
				gotCookie := &http.Cookie{
					Name:     cookie.Name,
					Value:    cookie.Value,
					Path:     cookie.Path,
					Expires:  time.Time{},
					HttpOnly: cookie.HttpOnly,
					Secure:   cookie.Secure,
					SameSite: cookie.SameSite,
				}
				wantCookie := &http.Cookie{
					Name:     tt.cookie.Name,
					Value:    tt.cookie.Value,
					Path:     tt.cookie.Path,
					Expires:  time.Time{},
					HttpOnly: tt.cookie.HttpOnly,
					Secure:   tt.cookie.Secure,
					SameSite: tt.cookie.SameSite,
				}
				if !reflect.DeepEqual(gotCookie, wantCookie) {
					t.Errorf("cookie = %v, want: %v", gotCookie, wantCookie)
				}

				if cookie.Expires.IsZero() {
					t.Errorf("cookie Expires field is zero, expected a future time")
				} else {
					expectedMin := time.Now().Add(23 * time.Hour)
					expectedMax := time.Now().Add(25 * time.Hour)

					if cookie.Expires.Before(expectedMin) || cookie.Expires.After(expectedMax) {
						t.Errorf("cookie Expires field (%q) is not within the expected range (%q - %q)",
							cookie.Expires.Format(time.RFC3339),
							expectedMin.Format(time.RFC3339),
							expectedMax.Format(time.RFC3339))
					}
				}
			}
		})
	}
}
