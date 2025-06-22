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
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func TestCSRFGuard(t *testing.T) {
	t.Parallel()

	const (
		headerCalled = "X-Header-Called"
		timeUnit     = time.Minute
	)

	defaultDuration := 30 * timeUnit

	cfg := &config.CSRF{
		CookieName:   "csrf_token",
		HeaderName:   "X-CSRF-Token",
		TokenLength:  32,
		CookieMaxAge: timex.Duration{Duration: defaultDuration},
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
					MaxAge:   int(defaultDuration.Seconds()),
				}, nil
			}},
			&http.Cookie{
				Name:     cfg.CookieName,
				Value:    base64.RawURLEncoding.EncodeToString([]byte("test_token")),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(defaultDuration.Seconds()),
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
				MaxAge:   int(defaultDuration.Seconds()),
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
		{
			"POST request with malformed token in header",
			http.MethodPost,
			http.StatusForbidden,
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
				MaxAge:   int(defaultDuration.Seconds()),
			},
			"test_token",
			"",
		},
		{
			"POST request with malformed token in cookie",
			http.MethodPost,
			http.StatusForbidden,
			"",
			&security.StubBaker{BakeFunc: func() (*http.Cookie, error) { return &http.Cookie{}, nil }},
			nil,
			&http.Cookie{
				Name:     cfg.CookieName,
				Value:    "test_token",
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(defaultDuration.Seconds()),
			},
			base64.RawURLEncoding.EncodeToString([]byte("test_token")),
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tc.method, "/", http.NoBody)
			rec := httptest.NewRecorder()
			if tc.prevCSRFHeader != "" {
				req.Header.Set(cfg.HeaderName, tc.prevCSRFHeader)
			}
			if tc.prevCookie != nil {
				req.AddCookie(tc.prevCookie)
			}

			mw := middleware.CSRFGuard(cfg, tc.stubBaker)(handler)
			mw.ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeader := rec.Header().Get(cfg.HeaderName)
			wantHeader := tc.csrfHeader
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", cfg.HeaderName, gotHeader, wantHeader)
			}

			gotHeaderCalled := rec.Header().Get(headerCalled)
			wantHeaderCalled := tc.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}

			if tc.cookie != nil {
				resp := rec.Result()
				defer resp.Body.Close()

				cookies := resp.Cookies()

				if len(cookies) == 0 {
					t.Fatal("no cookie was set")
				}

				gotLen, wantLen := len(cookies), 1
				if gotLen != wantLen {
					t.Fatalf("len(cookies) = %d, want: %d", gotLen, wantLen)
				}

				cookie := cookies[0]
				gotCookie := &http.Cookie{
					Name:     cookie.Name,
					Value:    cookie.Value,
					Path:     cookie.Path,
					MaxAge:   0,
					HttpOnly: cookie.HttpOnly,
					Secure:   cookie.Secure,
					SameSite: cookie.SameSite,
				}
				wantCookie := &http.Cookie{
					Name:     tc.cookie.Name,
					Value:    tc.cookie.Value,
					Path:     tc.cookie.Path,
					MaxAge:   0,
					HttpOnly: tc.cookie.HttpOnly,
					Secure:   tc.cookie.Secure,
					SameSite: tc.cookie.SameSite,
				}

				if !reflect.DeepEqual(gotCookie, wantCookie) {
					t.Errorf("cookie = %v, want: %v", gotCookie, wantCookie)
				}

				gotAge, wantAge := cookie.MaxAge, int(defaultDuration.Seconds())
				if gotAge != wantAge {
					t.Errorf("cookie.MaxAge = %d, want: %d", gotAge, wantAge)
				}
			}
		})
	}
}
