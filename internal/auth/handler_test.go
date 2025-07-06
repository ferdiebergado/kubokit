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
	"github.com/ferdiebergado/kubokit/internal/provider"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	testEmail = "test@example.com"
	testPass  = "test"
	timeUnit  = time.Minute
)

var defaultDuration = 30 * timeUnit

func TestHandler_RegisterUser(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(0)

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

			cfg := &config.Config{
				Cookie: &config.Cookie{
					Name:   "refresh_token",
					MaxAge: timex.Duration{Duration: defaultDuration},
				},
				CSRF: &config.CSRF{
					CookieName:   "csrf_token",
					HeaderName:   "X-CSRF-Token",
					TokenLength:  8,
					CookieMaxAge: timex.Duration{Duration: defaultDuration},
				},
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
			}

			signer := jwt.StubSigner{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "1", nil
				},
			}
			csrfBaker := security.StubBaker{
				BakeFunc: func() (*http.Cookie, error) {
					cookie := &http.Cookie{
						Name:     "X-CSRF-Token",
						Value:    "csrf123",
						Path:     "/",
						MaxAge:   int(defaultDuration.Seconds()),
						Secure:   true,
						SameSite: 0,
					}

					return cookie, nil
				},
			}

			provider := &provider.Provider{
				Cfg:       cfg,
				Signer:    &signer,
				CSRFBaker: &csrfBaker,
			}
			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)
			}

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

	tests := []struct {
		name                      string
		input                     auth.UserLoginRequest
		code                      int
		loginFunc                 func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error)
		verifyFunc                func(tokenString string) (string, error)
		bakeFunc                  func() (*http.Cookie, error)
		gotBody, wantBody         any
		refreshCookie, csrfCookie *http.Cookie
	}{
		{
			name: "Registered user with verified email",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			code: http.StatusOK,
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error) {
				return "test_access_token", "test_refresh_token", nil
			},
			verifyFunc: func(tokenString string) (string, error) {
				return testEmail, nil
			},
			bakeFunc: func() (*http.Cookie, error) {
				cookie := &http.Cookie{
					Name:     "csrf_token",
					Value:    "test_csrf_token",
					Path:     "/",
					SameSite: http.SameSiteStrictMode,
					MaxAge:   int(defaultDuration.Seconds()),
					Secure:   true,
				}
				return cookie, nil
			},
			gotBody: &web.OKResponse[auth.UserLoginResponse]{},
			wantBody: &web.OKResponse[auth.UserLoginResponse]{
				Message: auth.MsgLoggedIn,
				Data: auth.UserLoginResponse{
					AccessToken: "test_access_token",
				},
			},
			refreshCookie: &http.Cookie{
				Name:     "refresh_token",
				Value:    "test_refresh_token",
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(defaultDuration.Seconds()),
				HttpOnly: true,
				Secure:   true,
			},
			csrfCookie: &http.Cookie{
				Name:     "csrf_token",
				Value:    "test_csrf_token",
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(defaultDuration.Seconds()),
				Secure:   true,
			},
		},
		{
			name: "Registered user with email not yet verified",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error) {
				return "", "", auth.ErrUserNotVerified
			},
			verifyFunc: func(tokenString string) (string, error) {
				return "", nil
			},
			bakeFunc: func() (*http.Cookie, error) {
				cookie := &http.Cookie{}
				return cookie, nil
			},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
		},
		{
			name: "Unregistered user",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error) {
				return "", "", user.ErrNotFound
			},
			verifyFunc: func(tokenString string) (string, error) {
				return "", nil
			},
			bakeFunc: func() (*http.Cookie, error) {
				cookie := &http.Cookie{}
				return cookie, nil
			},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
		},
		{
			name: "Incorrect password",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: "anotherpass",
			},
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken string, err error) {
				return "", "", auth.ErrIncorrectPassword
			},
			verifyFunc: func(tokenString string) (string, error) {
				return "", nil
			},
			bakeFunc: func() (*http.Cookie, error) {
				cookie := &http.Cookie{}
				return cookie, nil
			},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
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
				CSRF: &config.CSRF{
					CookieName:   "csrf_token",
					HeaderName:   "X-CSRF-Token",
					TokenLength:  8,
					CookieMaxAge: timex.Duration{Duration: defaultDuration},
				},
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
			}
			baker := &security.StubBaker{
				BakeFunc: tc.bakeFunc,
			}
			provider := &provider.Provider{
				Cfg:       cfg,
				Signer:    signer,
				CSRFBaker: baker,
			}
			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := web.NewContextWithParams(context.Background(), tc.input)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/login", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.LoginUser(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}

			if err = json.Unmarshal(rec.Body.Bytes(), &tc.gotBody); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.gotBody, tc.wantBody) {
				t.Errorf("rec.Body = %+v, want: %+v", tc.gotBody, tc.wantBody)
			}

			cookies := rec.Result().Cookies()

			refreshCookie, err := web.FindCookie(cookies, cfg.Cookie.Name)
			if err != nil && tc.refreshCookie != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(refreshCookie, tc.refreshCookie) {
				t.Errorf("refreshCookie = %+v\n want: %+v", refreshCookie, tc.refreshCookie)
			}

			csrfCookie, err := web.FindCookie(cookies, cfg.CSRF.CookieName)
			if err != nil && tc.csrfCookie != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(csrfCookie, tc.csrfCookie) {
				t.Errorf("csrfCookie = %+v\n want: %+v", csrfCookie, tc.csrfCookie)
			}
		})
	}
}

func TestHandler_VerifyEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userID   string
		provider *provider.Provider
		svc      auth.AuthService
		code     int
		token    string
		ctx      context.Context
	}{
		{
			name:   "Email verified successfully",
			userID: "123",
			provider: &provider.Provider{
				Cfg: &config.Config{
					Cookie: &config.Cookie{
						Name:   "refresh_token",
						MaxAge: timex.Duration{Duration: defaultDuration},
					},
					CSRF: &config.CSRF{
						CookieName:   "csrf_token",
						HeaderName:   "X-CSRF-Token",
						TokenLength:  8,
						CookieMaxAge: timex.Duration{Duration: defaultDuration},
					},
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
				CSRFBaker: &security.StubBaker{},
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
			provider: &provider.Provider{
				Cfg: &config.Config{
					Cookie: &config.Cookie{
						Name:   "refresh_token",
						MaxAge: timex.Duration{Duration: defaultDuration},
					},
					CSRF: &config.CSRF{
						CookieName:   "csrf_token",
						HeaderName:   "X-CSRF-Token",
						TokenLength:  8,
						CookieMaxAge: timex.Duration{Duration: defaultDuration},
					},
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
				CSRFBaker: &security.StubBaker{},
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
			provider: &provider.Provider{
				Cfg: &config.Config{
					Cookie: &config.Cookie{
						Name:   "refresh_token",
						MaxAge: timex.Duration{Duration: defaultDuration},
					},
					CSRF: &config.CSRF{
						CookieName:   "csrf_token",
						HeaderName:   "X-CSRF-Token",
						TokenLength:  8,
						CookieMaxAge: timex.Duration{Duration: defaultDuration},
					},
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "123", nil
					},
				},
				CSRFBaker: &security.StubBaker{},
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

			authHandler, err := auth.NewHandler(tc.svc, tc.provider)
			if err != nil {
				t.Fatal(err)
			}

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
		providers *provider.Provider
		svc       auth.AuthService
		code      int
		ctx       context.Context
		params    auth.ResetPasswordRequest
	}{
		{
			name:   "Password was reset successfully",
			userID: "123",
			providers: &provider.Provider{
				Cfg: &config.Config{
					Cookie: &config.Cookie{
						Name:   "refresh_token",
						MaxAge: timex.Duration{Duration: defaultDuration},
					},
					CSRF: &config.CSRF{
						CookieName:   "csrf_token",
						HeaderName:   "X-CSRF-Token",
						TokenLength:  8,
						CookieMaxAge: timex.Duration{Duration: defaultDuration},
					},
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (string, error) {
						return "1", nil
					},
					SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
						return "xyz", nil
					},
				},
				CSRFBaker: &security.StubBaker{
					BakeFunc: func() (*http.Cookie, error) {
						cookie := &http.Cookie{
							Name:     "X-CSRF-Token",
							Value:    "csrf123",
							Path:     "/",
							MaxAge:   int(defaultDuration.Seconds()),
							Secure:   true,
							SameSite: 0,
						}

						return cookie, nil
					},
				},
			},
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

			authHandler, err := auth.NewHandler(tc.svc, tc.providers)
			if err != nil {
				t.Fatal(err)
			}
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
		csrfBaker                 web.Baker
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
			csrfBaker: &security.StubBaker{
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
			csrfBaker: &security.StubBaker{
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
			signer: &jwt.StubSigner{},
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
			csrfBaker: &security.StubBaker{
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
			csrfBaker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			signer:     &jwt.StubSigner{},
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
			csrfBaker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			signer:  &jwt.StubSigner{},
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
			csrfBaker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return nil
				},
			},
			signer:  &jwt.StubSigner{},
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
			csrfBaker: &security.StubBaker{
				CheckFunc: func(c *http.Cookie) error {
					return errors.New("mac mismatch")
				},
			},
			signer:     &jwt.StubSigner{},
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

			provider := &provider.Provider{
				Cfg:       cfg,
				Signer:    tc.signer,
				CSRFBaker: tc.csrfBaker,
			}
			svc := &auth.StubService{}
			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)

			}

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
