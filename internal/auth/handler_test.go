package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
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

func TestHandler_Register(t *testing.T) {
	t.Parallel()

	timeStamp := time.Now().Truncate(0)

	type testCase struct {
		name       string
		register   func(ctx context.Context, params auth.RegisterParams) (user.User, error)
		wantStatus int
		errMsg     string
		assertBody func(t *testing.T, body io.ReadCloser)
	}

	testCases := []testCase{
		{
			name: "user does not exists",
			register: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
				return user.User{
					Model: model.Model{
						ID:        "1",
						CreatedAt: timeStamp,
						UpdatedAt: timeStamp,
					},
					Email:        testEmail,
					PasswordHash: "hashed",
				}, nil
			},
			wantStatus: http.StatusCreated,
			assertBody: func(t *testing.T, res io.ReadCloser) {
				t.Helper()

				var body web.OKResponse[auth.RegisterResponse]
				if err := json.NewDecoder(res).Decode(&body); err != nil {
					t.Fatalf("Failed to decode json response: %v", err)
				}

				gotMsg, wantMsg := body.Message, auth.MsgRegisterSuccess
				if gotMsg != wantMsg {
					t.Errorf("body.Message = %q, want: %q", gotMsg, wantMsg)
				}

				regResponse := auth.RegisterResponse{
					ID:        "1",
					Email:     testEmail,
					CreatedAt: timeStamp,
					UpdatedAt: timeStamp,
				}
				gotData, wantData := body.Data, regResponse
				if !reflect.DeepEqual(gotData, wantData) {
					t.Errorf("body.Data = %+v, want: %+v", gotData, wantData)
				}
			},
		},
		{
			name: "user exists",
			register: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
				return user.User{}, auth.ErrExists
			},
			wantStatus: http.StatusConflict,
			errMsg:     auth.MsgUserExists,
		},
		{
			name: "db error",
			register: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
				return user.User{}, db.ErrQueryFailed
			},
			wantStatus: http.StatusInternalServerError,
			errMsg:     "an unexpected error occurred",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockService := &auth.StubService{
				RegisterFunc: tc.register,
			}

			provider := &auth.HandlerProvider{
				CfgJWT:    &config.JWT{},
				CfgCookie: &config.Cookie{},
			}

			handler, err := auth.NewHandler(mockService, provider)
			if err != nil {
				t.Fatalf("Failed to create handler: %v", err)
			}

			mockRequest := auth.RegisterRequest{
				Email:           testEmail,
				Password:        "testpass",
				PasswordConfirm: "testpass",
			}

			ctx := web.NewContextWithParams(context.Background(), mockRequest)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/register", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Register(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tc.wantStatus)
			}

			gotContent, wantContent := res.Header.Get(web.HeaderContentType), web.MimeJSON
			if gotContent != wantContent {
				t.Errorf("res.Header.Get(%q) = %q, want: %q", web.HeaderContentType, gotContent, wantContent)
			}

			if tc.errMsg != "" {
				var body web.ErrorResponse
				if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
					t.Fatalf("Failed to decode json response: %v", err)
				}

				if body.Message != tc.errMsg {
					t.Errorf("body.Message = %q, want: %q", body.Message, tc.errMsg)
				}

				return
			}

			tc.assertBody(t, res.Body)
		})
	}
}

func TestHandler_Login(t *testing.T) {
	t.Parallel()

	mockCfg := &config.Config{
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

	mockAuthData := &auth.AuthData{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    defaultDuration.Milliseconds(),
	}

	tests := []struct {
		name              string
		input             auth.LoginRequest
		code              int
		login             func(ctx context.Context, params auth.LoginParams) (*auth.AuthData, error)
		verify            func(tokenString string) (*jwt.Claims, error)
		gotBody, wantBody any
		wantRefreshCookie *http.Cookie
	}{
		{
			name: "Registered user with verified email",
			input: auth.LoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			code: http.StatusOK,
			login: func(ctx context.Context, params auth.LoginParams) (*auth.AuthData, error) {
				authData := &auth.AuthData{
					AccessToken:  mockAuthData.AccessToken,
					RefreshToken: mockAuthData.RefreshToken,
					TokenType:    mockAuthData.TokenType,
					ExpiresIn:    mockAuthData.ExpiresIn,
				}
				return authData, nil
			},
			verify: func(tokenString string) (*jwt.Claims, error) {
				return &jwt.Claims{UserID: testEmail}, nil
			},
			gotBody: &web.OKResponse[auth.LoginResponse]{},
			wantBody: &web.OKResponse[auth.LoginResponse]{
				Message: auth.MsgLoggedIn,
				Data: auth.LoginResponse{
					AccessToken:  mockAuthData.AccessToken,
					RefreshToken: mockAuthData.RefreshToken,
					ExpiresIn:    mockAuthData.ExpiresIn,
					TokenType:    mockAuthData.TokenType,
				},
			},
			wantRefreshCookie: &http.Cookie{
				Name:     mockCfg.Cookie.Name,
				Value:    mockAuthData.RefreshToken,
				Path:     "/",
				MaxAge:   int(defaultDuration.Seconds()),
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
		},
		{
			name: "Registered user with email not yet verified",
			input: auth.LoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			login: func(ctx context.Context, params auth.LoginParams) (*auth.AuthData, error) {
				return nil, auth.ErrNotVerified
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
			input: auth.LoginRequest{
				Email:    testEmail,
				Password: testPass,
			},
			login: func(ctx context.Context, params auth.LoginParams) (*auth.AuthData, error) {
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
			input: auth.LoginRequest{
				Email:    testEmail,
				Password: "anotherpass",
			},
			login: func(ctx context.Context, params auth.LoginParams) (*auth.AuthData, error) {
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
				LoginFunc: tc.login,
			}

			signer := &jwt.StubSigner{
				VerifyFunc: tc.verify,
			}

			provider := &auth.HandlerProvider{
				CfgJWT:    mockCfg.JWT,
				CfgCookie: mockCfg.Cookie,
				Signer:    signer,
			}
			authHandler, err := auth.NewHandler(svc, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := web.NewContextWithParams(context.Background(), tc.input)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/login", http.NoBody)
			req.Header.Set("User-Agent", "Chrome")
			rec := httptest.NewRecorder()
			authHandler.Login(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}

			res := rec.Result()
			defer res.Body.Close()

			if err = json.Unmarshal(rec.Body.Bytes(), &tc.gotBody); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.gotBody, tc.wantBody) {
				t.Errorf("rec.Body = %+v, want: %+v", tc.gotBody, tc.wantBody)
			}

			cookies := res.Cookies()

			if tc.wantRefreshCookie == nil {
				if len(cookies) > 0 {
					t.Errorf("response should not contain cookies")
				}
			} else {
				if len(cookies) == 0 {
					t.Fatalf("response should contain cookies")
				}

				gotRefreshCookie := findCookie(t, cookies, mockCfg.Cookie.Name)
				if gotRefreshCookie == nil {
					t.Fatalf("refresh cookie was not found in response")
				}

				if gotRefreshCookie.Name != tc.wantRefreshCookie.Name {
					t.Errorf("gotRefreshCookie.Name = %q, want: %q", gotRefreshCookie.Name, tc.wantRefreshCookie.Name)
				}

				if gotRefreshCookie.Value != tc.wantRefreshCookie.Value {
					t.Errorf("gotRefreshCookie.Value = %q, want: %q", gotRefreshCookie.Value, tc.wantRefreshCookie.Value)
				}

				if gotRefreshCookie.Path != tc.wantRefreshCookie.Path {
					t.Errorf("gotRefreshCookie.Path = %q, want: %q", gotRefreshCookie.Path, tc.wantRefreshCookie.Path)
				}

				if gotRefreshCookie.MaxAge != tc.wantRefreshCookie.MaxAge {
					t.Errorf("gotRefreshCookie.MaxAge = %d, want: %d", gotRefreshCookie.MaxAge, tc.wantRefreshCookie.MaxAge)
				}

				if int(gotRefreshCookie.SameSite) != int(tc.wantRefreshCookie.SameSite) {
					t.Errorf("gotRefreshCookie.SameSite = %d, want: %d", gotRefreshCookie.SameSite, tc.wantRefreshCookie.SameSite)
				}

				if !gotRefreshCookie.Secure {
					t.Errorf("gotRefreshCookie.Secure = %t, want: %t", gotRefreshCookie.Secure, tc.wantRefreshCookie.Secure)
				}

				if gotRefreshCookie.HttpOnly != tc.wantRefreshCookie.HttpOnly {
					t.Errorf("gotRefreshCookie.HttpOnly = %t, want: %t", gotRefreshCookie.HttpOnly, tc.wantRefreshCookie.HttpOnly)
				}
			}
		})
	}
}

func TestHandler_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		userID    string
		service   auth.Service
		cfgJWT    *config.JWT
		cfgCookie *config.Cookie
		cfgApp    *config.App
		signer    jwt.Signer
		code      int
		token     string
		request   *auth.VerifyRequest
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
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			code:    http.StatusOK,
			token:   "test_token",
			request: &auth.VerifyRequest{Token: "test_token"},
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
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return user.ErrNotFound
				},
			},
			code:    http.StatusUnauthorized,
			token:   "test_token",
			request: &auth.VerifyRequest{Token: "test_token"},
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
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return db.ErrQueryFailed
				},
			},
			code:    http.StatusInternalServerError,
			token:   "test_token",
			request: &auth.VerifyRequest{Token: "test_token"},
		},
		// TODO: test cases for expired token, invalid token
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &auth.HandlerProvider{
				CfgJWT:    tc.cfgJWT,
				CfgCookie: tc.cfgCookie,
				Signer:    tc.signer,
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
			authHandler.Verify(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}
		})
	}
}

func TestHandler_ChangePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		userID    string
		signer    jwt.Signer
		cfgJWT    *config.JWT
		cfgApp    *config.App
		cfgCookie *config.Cookie
		service   auth.Service
		code      int
		ctx       context.Context
		params    auth.ChangePasswordRequest
	}{
		{
			name:   "Password was changed successfully",
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
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return nil
				},
			},
			code: http.StatusOK,
			ctx:  user.NewContextWithUser(context.Background(), "123"),
			params: auth.ChangePasswordRequest{
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
				CfgJWT:    tc.cfgJWT,
				CfgCookie: tc.cfgCookie,
				Signer:    tc.signer,
			}
			authHandler, err := auth.NewHandler(tc.service, provider)
			if err != nil {
				t.Fatal(err)
			}
			ctx := web.NewContextWithParams(tc.ctx, tc.params)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/change-password", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.ChangePassword(rec, req)

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
		service       auth.Service
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
			gotBody: &web.OKResponse[auth.LoginResponse]{},
			wantBody: &web.OKResponse[auth.LoginResponse]{
				Message: "Token refreshed.",
				Data: auth.LoginResponse{
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

			provider := &auth.HandlerProvider{
				CfgJWT:    cfg.JWT,
				CfgCookie: cfg.Cookie,
				Signer:    tc.signer,
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

func TestHandler_Logout(t *testing.T) {
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
				LogoutFunc: tc.logoutFunc,
			}
			provider := &auth.HandlerProvider{
				CfgJWT: &config.JWT{},
				CfgCookie: &config.Cookie{
					Name: "refresh_token",
				},
				Signer: &jwt.StubSigner{},
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
					SameSite: http.SameSiteStrictMode,
				}
				req.AddCookie(refreshCookie)
			}

			rec := httptest.NewRecorder()
			authHandler.Logout(rec, req)

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

			if tc.withCookies {
				if len(cookies) != 1 {
					t.Fatal("there should be 2 cookies in the response")
				}

				wantRefreshCookie := &http.Cookie{
					Name:     "refresh_token",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					SameSite: http.SameSiteStrictMode,
					HttpOnly: true,
				}
				gotRefreshCookie := findCookie(t, cookies, "refresh_token")

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

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

func TestHandler_ResetPassword(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name          string
		resetPassword func(ctx context.Context, params auth.ResetPasswordParams) error
		wantStatus    int
		wantMsg       string
	}

	testcases := []testCase{
		{
			name: "user exists",
			resetPassword: func(ctx context.Context, params auth.ResetPasswordParams) error {
				return nil
			},
			wantStatus: http.StatusOK,
			wantMsg:    auth.MsgPasswordResetSuccess,
		},
		{
			name: "user does not exists",
			resetPassword: func(ctx context.Context, params auth.ResetPasswordParams) error {
				return user.ErrNotFound
			},
			wantStatus: http.StatusUnauthorized,
			wantMsg:    message.InvalidUser,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockService := &auth.StubService{
				ResetPasswordFunc: tc.resetPassword,
			}
			mockSigner := &jwt.StubSigner{}
			provider := &auth.HandlerProvider{
				CfgJWT:    &config.JWT{},
				CfgCookie: &config.Cookie{},
				Signer:    mockSigner,
			}
			handler, err := auth.NewHandler(mockService, provider)
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			resetReq := auth.ResetPasswordRequest{
				Password:        "testpass",
				PasswordConfirm: "testpass",
			}
			ctx := web.NewContextWithParams(context.Background(), resetReq)
			userCtx := user.NewContextWithUser(ctx, "1")
			req := httptest.NewRequestWithContext(userCtx, http.MethodPost, "/reset-password", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ResetPassword(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			gotStatus, wantStatus := res.StatusCode, tc.wantStatus
			if gotStatus != wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", gotStatus, wantStatus)
			}

			gotContent, wantContent := res.Header.Get(web.HeaderContentType), web.MimeJSON
			if gotContent != wantContent {
				t.Errorf("res.Header.Get(%q) = %q, want: %q", web.HeaderContentType, gotContent, wantContent)
			}

			var body map[string]string
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("Failed to decode json response: %v", err)
			}

			gotMsg, wantMsg := body["message"], tc.wantMsg
			if gotMsg != wantMsg {
				t.Errorf("body['message'] = %q, want: %q", body, tc.wantMsg)
			}
		})
	}
}
