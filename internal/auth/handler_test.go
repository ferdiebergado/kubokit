package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestHandler_RegisterUser(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(0)
	testEmail := "test@example.com"
	testPass := "test"

	tests := []struct {
		name        string
		params      auth.RegisterUserRequest
		regUserFunc func(ctx context.Context, params auth.RegisterUserParams) (user.User, error)
		code        int
		user        *auth.RegisterUserResponse
	}{
		{"Successful registration",
			auth.RegisterUserRequest{Email: testEmail, Password: testPass, PasswordConfirm: testPass},
			func(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
				return user.User{
					Model: model.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: testEmail,
				}, nil
			},
			http.StatusCreated,
			&auth.RegisterUserResponse{
				ID:        "1",
				Email:     testEmail,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		{"User already exists",
			auth.RegisterUserRequest{Email: testEmail, Password: testPass, PasswordConfirm: testPass},
			func(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
				return user.User{}, auth.ErrUserExists
			},
			http.StatusConflict,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := &auth.StubService{
				RegisterUserFunc: tt.regUserFunc,
			}

			provider := &auth.Provider{}
			authHandler := auth.NewHandler(svc, provider)

			paramsCtx := web.NewContextWithParams(context.Background(), tt.params)
			req := httptest.NewRequestWithContext(paramsCtx, http.MethodPost, "/auth/register", nil)
			rec := httptest.NewRecorder()
			authHandler.RegisterUser(rec, req)

			gotStatus, wantStatus := rec.Code, tt.code
			if gotStatus != wantStatus {
				t.Errorf(message.FmtErrStatusCode, gotStatus, wantStatus)
			}

			gotHeader := rec.Header().Get(web.HeaderContentType)
			wantHeader := web.MimeJSON
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", web.HeaderContentType, gotHeader, wantHeader)
			}

			if tt.user != nil {
				var apiRes web.OKResponse[*auth.RegisterUserResponse]
				if err := json.NewDecoder(rec.Body).Decode(&apiRes); err != nil {
					t.Fatal(err)
				}

				gotUser, wantUser := apiRes.Data, tt.user
				if !reflect.DeepEqual(gotUser, wantUser) {
					t.Errorf("apiRes.Data = %+v, want: %+v", gotUser, wantUser)
				}
			}
		})
	}
}

func TestHandler_LoginUser(t *testing.T) {
	t.Parallel()

	const (
		testEmail = "test@example.com"
		testPass  = "test"
		timeUnit  = time.Minute
	)

	defaultDuration := 30 * timeUnit

	tests := []struct {
		name       string
		input      auth.UserLoginRequest
		code       int
		loginFunc  func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error)
		verifyFunc func(tokenString string) (string, error)
		bakeFunc   func() (*http.Cookie, error)
	}{
		{
			name: "Registered user with verified email",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			code: http.StatusOK,
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error) {
				return "access_token", "refresh_token", nil
			},
			verifyFunc: func(tokenString string) (string, error) {
				return testEmail, nil
			},
			bakeFunc: func() (*http.Cookie, error) {
				return &http.Cookie{}, nil
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := &auth.StubService{
				LoginUserFunc: tc.loginFunc,
			}
			signer := &jwt.StubSigner{
				VerifyFunc: tc.verifyFunc,
			}
			cfg := &config.Config{
				Cookie: &config.Cookie{
					Name:   "refresh_token",
					MaxAge: timex.Duration{Duration: defaultDuration},
				},
			}
			baker := &security.StubBaker{
				BakeFunc: tc.bakeFunc,
			}
			provider := &auth.Provider{
				Cfg:       cfg,
				Signer:    signer,
				CSRFBaker: baker,
			}
			authHandler := auth.NewHandler(svc, provider)

			ctx := web.NewContextWithParams(context.Background(), tc.input)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/login", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.LoginUser(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}
		})
	}
}

func TestHandler_VerifyEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userID   string
		provider *auth.Provider
		svc      auth.AuthService
		code     int
		token    string
		ctx      context.Context
	}{
		{
			name:   "Email verified successfully",
			userID: "123",
			provider: &auth.Provider{
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
			},
			svc: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			code:  http.StatusOK,
			token: "test_token",
			ctx:   user.NewContextWithUser(context.Background(), "123"),
		},
		{
			name:   "User does not exists",
			userID: "123",
			provider: &auth.Provider{
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
			},
			svc: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return user.ErrNotFound
				},
			},
			code:  http.StatusNotFound,
			token: "test_token",
			ctx:   user.NewContextWithUser(context.Background(), "123"),
		},
		{
			name:   "Verification failed due to database error",
			userID: "123",
			provider: &auth.Provider{
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
			},
			svc: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return errors.New("query failed")
				},
			},
			code:  http.StatusInternalServerError,
			token: "test_token",
			ctx:   user.NewContextWithUser(context.Background(), "123"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authHandler := auth.NewHandler(tc.svc, tc.provider)
			req := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/auth/verify?token="+tc.token, http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.VerifyEmail(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}
		})
	}
}

func TestHandler_ResetPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		userID    string
		providers *auth.Provider
		svc       auth.AuthService
		code      int
		ctx       context.Context
		params    auth.ResetPasswordRequest
	}{
		{
			name:      "Password was reset successfully",
			userID:    "123",
			providers: &auth.Provider{},
			svc: &auth.StubService{
				ResetPasswordFunc: func(ctx context.Context, params auth.ResetPasswordParams) error {
					return nil
				},
			},
			code: http.StatusOK,
			ctx:  user.NewContextWithUser(context.Background(), "123"),
			params: auth.ResetPasswordRequest{
				CurrentPassword: "oldtest",
				NewPassword:     "test",
				RepeatPassword:  "test",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authHandler := auth.NewHandler(tc.svc, tc.providers)
			ctx := web.NewContextWithParams(tc.ctx, tc.params)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/reset", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.ResetPassword(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}
		})
	}
}

func TestHandler_RefreshToken(t *testing.T) {
	t.Parallel()

	const (
		userID       = "1"
		csrfToken    = "abc"
		refreshToken = "123"
		accessToken  = "xyz"
		timeUnit     = time.Minute
	)

	defaultDuration := 30 * timeUnit

	cfg := &config.Config{
		Cookie: &config.Cookie{
			Name:   "refresh_token",
			MaxAge: timex.Duration{Duration: defaultDuration},
		},
		CSRF: &config.CSRF{
			HeaderName:   "X-CSRF-Token",
			CookieName:   "csrf_token",
			TokenLength:  8,
			CookieMaxAge: timex.Duration{Duration: defaultDuration},
		},
		JWT: &config.JWT{
			JTILength:  8,
			Issuer:     "test@example.com",
			TTL:        timex.Duration{Duration: defaultDuration},
			RefreshTTL: timex.Duration{Duration: defaultDuration},
		},
	}

	tests := []struct {
		name                      string
		refreshCookie, csrfCookie *http.Cookie
		csrfHeader                string
		signer                    jwt.Signer
		baker                     web.Baker
		code                      int
		gotBody                   any
		wantBody                  any
	}{
		{
			name: "With valid refresh, csrf tokens and header",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			csrfCookie: &http.Cookie{
				Name:     cfg.CSRF.CookieName,
				Value:    "abc",
				MaxAge:   int(cfg.CSRF.CookieMaxAge.Duration),
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			csrfHeader: "abc",
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (string, error) {
					return "1", nil
				},
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "xyz", nil
				},
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			code:    http.StatusOK,
			gotBody: &web.OKResponse[auth.UserLoginResponse]{},
			wantBody: &web.OKResponse[auth.UserLoginResponse]{
				Message: "Token refreshed.",
				Data: auth.UserLoginResponse{
					AccessToken: "xyz",
				},
			},
		},
		{
			name: "Missing refresh cookie",
			csrfCookie: &http.Cookie{
				Name:     cfg.CSRF.CookieName,
				Value:    "abc",
				MaxAge:   int(cfg.CSRF.CookieMaxAge.Duration),
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			csrfHeader: "abc",
			code:       http.StatusUnauthorized,
			gotBody:    &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
		},
		{
			name: "Expired refresh cookie",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			csrfCookie: &http.Cookie{
				Name:     cfg.CSRF.CookieName,
				Value:    "abc",
				MaxAge:   int(cfg.CSRF.CookieMaxAge.Duration),
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			csrfHeader: "abc",
			code:       http.StatusUnauthorized,
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (string, error) {
					return "", errors.New("token is expired")
				},
			},
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
		},
		{
			name: "Missing csrf cookie",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			csrfHeader: "abc",
			code:       http.StatusForbidden,
			gotBody:    &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidInput,
			},
		},
		{
			name: "Missing csrf header",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			csrfCookie: &http.Cookie{
				Name:     cfg.CSRF.CookieName,
				Value:    "abc",
				MaxAge:   int(cfg.CSRF.CookieMaxAge.Duration),
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			code:    http.StatusForbidden,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidInput,
			},
		},
		{
			name: "Missing csrf cookie and header",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			code:    http.StatusForbidden,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidInput,
			},
		},
		{
			name: "Invalid csrf signature",
			refreshCookie: &http.Cookie{
				Name:     cfg.Cookie.Name,
				Value:    "123",
				MaxAge:   int(cfg.Cookie.MaxAge.Duration),
				Secure:   true,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			csrfCookie: &http.Cookie{
				Name:     cfg.CSRF.CookieName,
				Value:    "abc",
				MaxAge:   int(cfg.CSRF.CookieMaxAge.Duration),
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			},
			baker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return errors.New("mac mismatch")
				},
			},
			csrfHeader: "abc",
			code:       http.StatusForbidden,
			gotBody:    &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidInput,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &auth.Provider{
				Cfg:       cfg,
				Signer:    tc.signer,
				CSRFBaker: tc.baker,
			}
			svc := &auth.StubService{}
			authHandler := auth.NewHandler(svc, provider)

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			if tc.refreshCookie != nil {
				req.AddCookie(tc.refreshCookie)
			}
			if tc.csrfCookie != nil {
				req.AddCookie(tc.csrfCookie)
			}
			if tc.csrfHeader != "" {
				req.Header.Set(cfg.CSRF.HeaderName, tc.csrfHeader)
			}
			rec := httptest.NewRecorder()
			authHandler.RefreshToken(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}

			if err := json.Unmarshal(rec.Body.Bytes(), &tc.gotBody); err != nil {
				t.Fatalf("unmarshal response body: %v", err)
			}

			if !reflect.DeepEqual(tc.gotBody, tc.wantBody) {
				t.Errorf("rec.Body = %+v, want: %+v", tc.gotBody, tc.wantBody)
			}
		})
	}
}
