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
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
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
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
				App: &config.App{
					ClientURL: "http://127.0.0.1:5173",
				},
				Cookie: &config.Cookie{
					Name: "refresh_token",
				},
			}

			signer := &jwt.StubSigner{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "1", nil
				},
			}

			csrfBaker := &security.StubCSRFCookieBaker{}

			provider := &auth.HandlerProvider{
				CfgJWT:          cfg.JWT,
				CfgCookie:       cfg.Cookie,
				Signer:          signer,
				CSRFCookieBaker: csrfBaker,
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
		name              string
		input             auth.UserLoginRequest
		code              int
		loginFunc         func(ctx context.Context, params auth.LoginUserParams) (*auth.AuthData, error)
		verifyFunc        func(tokenString string) (*jwt.Claims, error)
		gotBody, wantBody any
	}{
		{
			name: "Registered user with verified email",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			code: http.StatusOK,
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (*auth.AuthData, error) {
				secret := &auth.AuthData{
					AccessToken:  "test_access_token",
					RefreshToken: "test_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    defaultDuration.Milliseconds(),
				}

				return secret, nil
			},
			verifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return &jwt.Claims{UserID: testEmail}, nil
			},
			gotBody: &web.OKResponse[auth.UserLoginResponse]{},
			wantBody: &web.OKResponse[auth.UserLoginResponse]{
				Message: auth.MsgLoggedIn,
				Data: auth.UserLoginResponse{
					AccessToken:  "test_access_token",
					RefreshToken: "test_refresh_token",
					ExpiresIn:    defaultDuration.Milliseconds(),
					TokenType:    "Bearer",
				},
			},
		},
		{
			name: "Registered user with email not yet verified",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (*auth.AuthData, error) {
				return nil, auth.ErrUserNotVerified
			},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: auth.MsgNotVerified,
				Details: map[string]string{"error_code": "ACCOUNT_NOT_VERIFIED"},
			},
		},
		{
			name: "Unregistered user",
			input: auth.UserLoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (*auth.AuthData, error) {
				return nil, user.ErrNotFound
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
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (*auth.AuthData, error) {
				return nil, auth.ErrIncorrectPassword
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

			csrfBaker := &security.StubCSRFCookieBaker{
				BakeFunc: func() (*http.Cookie, error) {
					return &http.Cookie{}, nil
				},
			}

			cfg := &config.Config{
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
				Cookie: &config.Cookie{
					Name: "refresh_token",
				},
			}

			provider := &auth.HandlerProvider{
				CfgJWT:          cfg.JWT,
				CfgCookie:       cfg.Cookie,
				Signer:          signer,
				CSRFCookieBaker: csrfBaker,
			}
			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := web.NewContextWithParams(context.Background(), tc.input)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/login", http.NoBody)
			req.Header.Set("User-Agent", "Chrome")
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
		})
	}
}

func TestHandler_VerifyUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		userID    string
		service   auth.AuthService
		cfgJWT    *config.JWT
		cfgCookie *config.Cookie
		cfgApp    *config.App
		signer    jwt.Signer
		csfrBaker web.Baker
		code      int
		token     string
		request   *auth.VerifyUserRequest
	}{
		{
			name:   "Email verified successfully",
			userID: "123",
			cfgJWT: &config.JWT{
				JTILength:  8,
				Issuer:     "example.com",
				TTL:        timex.Duration{Duration: defaultDuration},
				RefreshTTL: timex.Duration{Duration: defaultDuration},
			},
			cfgApp: &config.App{
				ClientURL: "http://127.0.0.1:5173",
			},
			cfgCookie: &config.Cookie{
				Name: "refresh_token",
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "123"}, nil
				},
			},
			csfrBaker: &security.StubCSRFCookieBaker{},
			service: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			code:    http.StatusOK,
			token:   "test_token",
			request: &auth.VerifyUserRequest{Token: "test_token"},
		},
		{
			name:   "User does not exists",
			userID: "123",
			cfgJWT: &config.JWT{
				JTILength:  8,
				Issuer:     "example.com",
				TTL:        timex.Duration{Duration: defaultDuration},
				RefreshTTL: timex.Duration{Duration: defaultDuration},
			},
			cfgApp: &config.App{
				ClientURL: "http://127.0.0.1:5173",
			},
			cfgCookie: &config.Cookie{
				Name: "refresh_token",
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "123"}, nil
				},
			},
			csfrBaker: &security.StubCSRFCookieBaker{},
			service: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return user.ErrNotFound
				},
			},
			code:    http.StatusUnauthorized,
			token:   "test_token",
			request: &auth.VerifyUserRequest{Token: "test_token"},
		},
		{
			name:   "Verification failed due to database error",
			userID: "123",
			cfgJWT: &config.JWT{
				JTILength:  8,
				Issuer:     "example.com",
				TTL:        timex.Duration{Duration: defaultDuration},
				RefreshTTL: timex.Duration{Duration: defaultDuration},
			},
			cfgApp: &config.App{
				ClientURL: "http://127.0.0.1:5173",
			},
			cfgCookie: &config.Cookie{
				Name: "refresh_token",
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "123"}, nil
				},
			},
			csfrBaker: &security.StubCSRFCookieBaker{},
			service: &auth.StubService{
				VerifyUserfunc: func(ctx context.Context, token string) error {
					return db.ErrQueryFailed
				},
			},
			code:    http.StatusInternalServerError,
			token:   "test_token",
			request: &auth.VerifyUserRequest{Token: "test_token"},
		},
		// TODO: test cases for expired token, invalid token
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &auth.HandlerProvider{
				CfgJWT:          tc.cfgJWT,
				CfgCookie:       tc.cfgCookie,
				Signer:          tc.signer,
				CSRFCookieBaker: tc.csfrBaker,
			}
			authHandler, err := auth.NewHandler(tc.service, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if tc.request != nil {
				ctx = web.NewContextWithParams(ctx, *tc.request)
			}

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/verify", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.VerifyUser(rec, req)

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
		signer    jwt.Signer
		cfgJWT    *config.JWT
		cfgApp    *config.App
		cfgCookie *config.Cookie
		csrfBaker web.Baker
		service   auth.AuthService
		code      int
		ctx       context.Context
		params    auth.ResetPasswordRequest
	}{
		{
			name:   "Password was reset successfully",
			userID: "123",
			cfgJWT: &config.JWT{
				JTILength:  8,
				Issuer:     "example.com",
				TTL:        timex.Duration{Duration: defaultDuration},
				RefreshTTL: timex.Duration{Duration: defaultDuration},
			},
			cfgApp: &config.App{
				ClientURL: "http://127.0.0.1:5173",
			},
			cfgCookie: &config.Cookie{
				Name: "refresh_token",
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "1"}, nil
				},
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "xyz", nil
				},
			},
			csrfBaker: &security.StubCSRFCookieBaker{},
			service: &auth.StubService{
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

			provider := &auth.HandlerProvider{
				CfgJWT:          tc.cfgJWT,
				CfgCookie:       tc.cfgCookie,
				Signer:          tc.signer,
				CSRFCookieBaker: tc.csrfBaker,
			}
			authHandler, err := auth.NewHandler(tc.service, provider)
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
		JWT: &config.JWT{
			JTILength:  8,
			Issuer:     "test@example.com",
			TTL:        timex.Duration{Duration: defaultDuration},
			RefreshTTL: timex.Duration{Duration: defaultDuration},
		},
		App: &config.App{
			ClientURL: "http://127.0.0.1:5173",
		},
		Cookie: &config.Cookie{
			Name: "refresh_token",
		},
	}

	tests := []struct {
		name          string
		refreshCookie *http.Cookie
		service       auth.AuthService
		signer        jwt.Signer
		code          int
		gotBody       any
		wantBody      any
	}{
		{
			name: "With valid refresh token",
			refreshCookie: &http.Cookie{
				Name:     "refresh_token",
				Value:    "abc123",
				Secure:   true,
				MaxAge:   int(defaultDuration.Milliseconds()),
				HttpOnly: true,
				SameSite: http.SameSiteNoneMode,
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "1"}, nil
				},
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "access_token", nil
				},
			},
			service: &auth.StubService{
				RefreshTokenFunc: func(token string) (*auth.AuthData, error) {
					secret := &auth.AuthData{
						AccessToken:  "new_access_token",
						RefreshToken: "new_refresh_token",
						TokenType:    "Bearer",
						ExpiresIn:    defaultDuration.Milliseconds(),
					}
					return secret, nil
				},
			},
			code:    http.StatusOK,
			gotBody: &web.OKResponse[auth.UserLoginResponse]{},
			wantBody: &web.OKResponse[auth.UserLoginResponse]{
				Message: "Token refreshed.",
				Data: auth.UserLoginResponse{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    defaultDuration.Milliseconds(),
				},
			},
		},
		{
			name:    "Missing refresh token",
			service: &auth.StubService{},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
			signer: &jwt.StubSigner{},
		},
		{
			name: "Expired refresh token",
			refreshCookie: &http.Cookie{
				Name:     "refresh_token",
				Value:    "abc123",
				Secure:   true,
				MaxAge:   -1,
				HttpOnly: true,
				SameSite: http.SameSiteNoneMode,
			},
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return nil, errors.New("token is expired")
				},
			},
			service: &auth.StubService{
				RefreshTokenFunc: func(token string) (*auth.AuthData, error) {
					return nil, auth.ErrInvalidToken
				},
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

			csrfBaker := &security.StubCSRFCookieBaker{
				BakeFunc: func() (*http.Cookie, error) {
					return &http.Cookie{}, nil
				},
			}

			provider := &auth.HandlerProvider{
				CfgJWT:          cfg.JWT,
				CfgCookie:       cfg.Cookie,
				Signer:          tc.signer,
				CSRFCookieBaker: csrfBaker,
			}
			authHandler, err := auth.NewHandler(tc.service, provider)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			if tc.refreshCookie != nil {
				req.AddCookie(tc.refreshCookie)
			}
			rec := httptest.NewRecorder()
			authHandler.RefreshToken(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}

			if err := json.Unmarshal(rec.Body.Bytes(), &tc.gotBody); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.gotBody, tc.wantBody) {
				t.Errorf("rec.Body = %+v, want: %+v", tc.gotBody, tc.wantBody)
			}
		})
	}
}

func TestHandler_LogoutUser(t *testing.T) {
	type testCase struct {
		name        string
		withCookies bool
		logoutFunc  func(string) error
		code        int
		message     string
	}

	testCases := []testCase{
		{
			name:        "should return 204 and delete cookies when token is valid",
			withCookies: true,
			logoutFunc:  func(s string) error { return nil },
			code:        http.StatusNoContent,
		},
		{
			name:       "should return 401 when token is invalid",
			logoutFunc: func(s string) error { return auth.ErrInvalidToken },
			code:       http.StatusUnauthorized,
			message:    message.InvalidUser,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &auth.StubService{
				LogoutUserFunc: tc.logoutFunc,
			}
			provider := &auth.HandlerProvider{
				CfgJWT: &config.JWT{},
				CfgCookie: &config.Cookie{
					Name: "refresh_token",
				},
				CfgCSRF: &config.CSRF{
					CookieName: "csrf_token",
				},
				Signer: &jwt.StubSigner{},
				CSRFCookieBaker: &security.StubCSRFCookieBaker{
					BakeFunc: func() (*http.Cookie, error) {
						return &http.Cookie{
							Name:   "csrf_token",
							Value:  "123",
							Path:   "/",
							MaxAge: 18000,
						}, nil
					},
				},
			}

			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)
			}

			logoutRequest := auth.LogoutRequest{
				AccessToken: "123",
			}

			ctx := web.NewContextWithParams(context.Background(), logoutRequest)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/logout", http.NoBody)

			if tc.withCookies {
				refreshCookie := &http.Cookie{
					Name:     "refresh_token",
					Value:    "123",
					Path:     "/",
					MaxAge:   36000,
					HttpOnly: true,
					SameSite: http.SameSiteNoneMode,
				}
				req.AddCookie(refreshCookie)

				csrfCookie := &http.Cookie{
					Name:     "csrf_token",
					Value:    "abc",
					Path:     "/",
					MaxAge:   36000,
					SameSite: http.SameSiteNoneMode,
				}
				req.AddCookie(csrfCookie)
			}

			rec := httptest.NewRecorder()
			authHandler.LogoutUser(rec, req)

			wantCode, gotCode := tc.code, rec.Code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			result := rec.Result()

			defer result.Body.Close()

			var body map[string]string
			err = json.Unmarshal(rec.Body.Bytes(), &body)
			if err != nil {
				t.Fatal(err)
			}

			wantMsg, gotMsg := tc.message, body["message"]
			if gotMsg != wantMsg {
				t.Errorf("rec.Body.String() = %q, want: %q", gotMsg, wantMsg)
			}

			cookies := result.Cookies()
			findCookie := func(cookies []*http.Cookie, name string) *http.Cookie {
				for _, cookie := range cookies {
					if cookie.Name == name {
						return cookie
					}
				}

				return nil
			}

			if tc.withCookies {
				if len(cookies) != 2 {
					t.Fatal("there should be 2 cookies in the response")
				}

				wantCRSFCookie := &http.Cookie{
					Name:     "csrf_token",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					SameSite: http.SameSiteNoneMode,
				}
				gotCSRFCookie := findCookie(cookies, "csrf_token")

				if gotCSRFCookie.Name != wantCRSFCookie.Name {
					t.Errorf("gotCSRFCookie.Name = %q, want: %q", gotCSRFCookie.Name, wantCRSFCookie.Name)
				}

				if gotCSRFCookie.Value != wantCRSFCookie.Value {
					t.Errorf("gotCSRFCookie.Value = %q, want: %q", gotCSRFCookie.Value, wantCRSFCookie.Value)
				}

				if gotCSRFCookie.Path != wantCRSFCookie.Path {
					t.Errorf("gotCSRFCookie.Path = %q, want: %q", gotCSRFCookie.Path, wantCRSFCookie.Path)
				}

				if gotCSRFCookie.MaxAge != wantCRSFCookie.MaxAge {
					t.Errorf("gotCSRFCookie.MaxAge = %d, want: %d", gotCSRFCookie.MaxAge, wantCRSFCookie.MaxAge)
				}

				if int(gotCSRFCookie.SameSite) != int(wantCRSFCookie.SameSite) {
					t.Errorf("gotCSRFCookie.SameSite = %d, want: %d", gotCSRFCookie.SameSite, wantCRSFCookie.SameSite)
				}

				wantRefreshCookie := &http.Cookie{
					Name:     "refresh_token",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					SameSite: http.SameSiteNoneMode,
					HttpOnly: true,
				}
				gotRefreshCookie := findCookie(cookies, "refresh_token")

				if gotRefreshCookie.Name != wantRefreshCookie.Name {
					t.Errorf("gotRefreshCookie.Name = %q, want: %q", gotRefreshCookie.Name, wantRefreshCookie.Name)
				}

				if gotRefreshCookie.Value != wantRefreshCookie.Value {
					t.Errorf("gotRefreshCookie.Value = %q, want: %q", gotRefreshCookie.Value, wantRefreshCookie.Value)
				}

				if gotRefreshCookie.Path != wantRefreshCookie.Path {
					t.Errorf("gotRefreshCookie.Path = %q, want: %q", gotRefreshCookie.Path, wantRefreshCookie.Path)
				}

				if gotRefreshCookie.MaxAge != wantRefreshCookie.MaxAge {
					t.Errorf("gotRefreshCookie.MaxAge = %d, want: %d", gotRefreshCookie.MaxAge, wantRefreshCookie.MaxAge)
				}

				if int(gotRefreshCookie.SameSite) != int(wantRefreshCookie.SameSite) {
					t.Errorf("gotRefreshCookie.SameSite = %d, want: %d", gotRefreshCookie.SameSite, wantRefreshCookie.SameSite)
				}

				if gotRefreshCookie.HttpOnly != wantRefreshCookie.HttpOnly {
					t.Errorf("gotRefreshCookie.HttpOnly = %t, want: %t", gotRefreshCookie.HttpOnly, wantRefreshCookie.HttpOnly)
				}
			}
		})
	}
}
