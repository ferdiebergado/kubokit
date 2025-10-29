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
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
	}

	testCases := []testCase{
		{
			name: "user does not exists",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
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
			},
			wantStatus: http.StatusCreated,
			wantBody: map[string]any{
				"message": auth.MsgRegisterSuccess,
				"data": map[string]any{
					"id":         "1",
					"email":      testEmail,
					"created_at": timeStamp.Format(time.RFC3339Nano),
					"updated_at": timeStamp.Format(time.RFC3339Nano),
				},
			},
		},
		{
			name: "user exists",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{}, auth.ErrExists
				},
			},
			wantStatus: http.StatusConflict,
			wantBody: map[string]any{
				"message": auth.MsgUserExists,
			},
		},
		{
			name: "db error",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{}, db.ErrQueryFailed
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, err := auth.NewHandler(tc.service, &config.JWT{}, &config.Cookie{})
			if err != nil {
				t.Fatalf("Failed to create the handler: %v", err)
			}

			mockRequest := auth.RegisterRequest{
				Email:           testEmail,
				Password:        testPass,
				PasswordConfirm: testPass,
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

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tc.wantBody) {
				t.Errorf("body = %v, want: %v", body, tc.wantBody)
			}
		})
	}
}

func TestHandler_Login(t *testing.T) {
	t.Parallel()

	const (
		cookieName   = "refresh_token"
		maxAge       = 1000
		accessToken  = "mock_access_token"
		refreshToken = "mock_refresh_token"
	)

	type testCase struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
		wantCookie *http.Cookie
	}

	testCases := []testCase{
		{
			name: "user exists and verified with correct password",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
						ExpiresIn:    maxAge,
						TokenType:    "Bearer",
						User: &auth.UserInfo{
							ID:    "1",
							Email: testEmail,
						},
					}, nil
				},
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgLoggedIn,
				"data": map[string]any{
					"access_token":  "mock_access_token",
					"refresh_token": "mock_refresh_token",
					"expires_in":    float64(1000),
					"token_type":    "Bearer",
					"user": map[string]any{
						"id":    "1",
						"email": testEmail,
					},
				},
			},
			wantCookie: &http.Cookie{
				Name:     cookieName,
				Value:    refreshToken,
				Path:     "/",
				MaxAge:   maxAge,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
		},
		{
			name: "user exists but not yet verified",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, auth.ErrNotVerified
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgNotVerified,
				"error": map[string]any{
					"error_code": "ACCOUNT_NOT_VERIFIED",
				},
			},
		},
		{
			name: "user does not exists",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, user.ErrNotFound
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "user exists and verified but with incorrect password",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, auth.ErrIncorrectPassword
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "db error",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, db.ErrQueryFailed
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfgJWT := &config.JWT{
				RefreshTTL: timex.Duration{Duration: maxAge * time.Second},
			}
			cfgCookie := &config.Cookie{
				Name: cookieName,
			}

			handler, err := auth.NewHandler(tc.service, cfgJWT, cfgCookie)
			if err != nil {
				t.Fatalf("Failed to create handler: %v", err)
			}

			params := auth.LoginRequest{
				Email:    testEmail,
				Password: testPass,
			}
			ctx := web.NewContextWithParams(context.Background(), params)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Login(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tc.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tc.wantBody) {
				t.Errorf("body = %v, want: %v", body, tc.wantBody)
			}

			cookies := res.Cookies()
			numCookies := len(cookies)

			if tc.wantCookie != nil {
				if numCookies == 0 {
					t.Fatal("no cookies found in the response")
				}

				assertCookie(t, cookies[0], tc.wantCookie)
			} else if numCookies > 0 {
				t.Errorf("len(cookies) = %d, want: %d", numCookies, 0)
			}
		})
	}
}

func TestHandler_Verify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
	}

	testCases := []testCase{
		{
			name: "valid verification token",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgVerifySuccess,
			},
		},
		{
			name: "invalid verification token",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return errors.New("malformed token")
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "db error",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return db.ErrQueryFailed
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := auth.NewHandler(tc.service, &config.JWT{}, &config.Cookie{})
			if err != nil {
				t.Fatalf("Failed to create the handler: %v", err)
			}

			mockRequest := auth.VerifyRequest{
				Token: "mock_token",
			}
			ctx := web.NewContextWithParams(context.Background(), mockRequest)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/verify", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Verify(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tc.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tc.wantBody) {
				t.Errorf("body = %v, want: %v", body, tc.wantBody)
			}
		})
	}
}

func TestHandler_ChangePassword(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		service    auth.Service
		userID     string
		wantStatus int
		wantBody   map[string]any
	}

	testCases := []testCase{
		{
			name: "password change success",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return nil
				},
			},
			userID:     "1",
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgSuccessPasswordChanged,
			},
		},
		{
			name:       "user is not authenticated",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "user does not exists",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return user.ErrNotFound
				},
			},
			userID:     "1",
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "current password is incorrect",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return auth.ErrIncorrectPassword
				},
			},
			userID:     "1",
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "db error",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return db.ErrQueryFailed
				},
			},
			userID:     "1",
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, err := auth.NewHandler(tc.service, &config.JWT{}, &config.Cookie{})
			if err != nil {
				t.Fatalf("Failed to create the handler: %v", err)
			}

			params := auth.ChangePasswordRequest{
				CurrentPassword: "mock_current_password",
				NewPassword:     "mock_new_password",
				RepeatPassword:  "mock_new_password",
			}
			ctx := web.NewContextWithParams(context.Background(), params)
			ctx = auth.ContextWithUser(ctx, tc.userID)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/change-password", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ChangePassword(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tc.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tc.wantBody) {
				t.Errorf("body = %v, want: %v", body, tc.wantBody)
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
				RefreshTokenFunc: func(token string) (*auth.Session, error) {
					secret := &auth.Session{
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
				Message: auth.MsgInvalidUser,
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
				RefreshTokenFunc: func(token string) (*auth.Session, error) {
					return nil, auth.ErrInvalidToken
				},
			},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: auth.MsgInvalidUser,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authHandler, err := auth.NewHandler(tc.service, cfg.JWT, cfg.Cookie)
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
			message:    auth.MsgInvalidUser,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &auth.StubService{
				LogoutFunc: tc.logoutFunc,
			}

			cfgCookie := &config.Cookie{
				Name: "refresh_token",
			}

			authHandler, err := auth.NewHandler(svc, &config.JWT{}, cfgCookie)
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
			wantMsg:    auth.MsgInvalidUser,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockService := &auth.StubService{
				ResetPasswordFunc: tc.resetPassword,
			}

			handler, err := auth.NewHandler(mockService, &config.JWT{}, &config.Cookie{})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			resetReq := auth.ResetPasswordRequest{
				Password:        testPass,
				PasswordConfirm: testPass,
			}
			ctx := web.NewContextWithParams(context.Background(), resetReq)
			userCtx := auth.ContextWithUser(ctx, "1")
			req := httptest.NewRequestWithContext(userCtx, http.MethodPost, "/reset-password", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ResetPassword(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			gotStatus, wantStatus := res.StatusCode, tc.wantStatus
			if gotStatus != wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", gotStatus, wantStatus)
			}

			web.AssertContentType(t, res)

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

func assertCookie(t *testing.T, responseCookie, wantCookie *http.Cookie) {
	t.Helper()

	if responseCookie.Value != wantCookie.Value {
		t.Errorf("responseCookie.Value = %q, want: %q", responseCookie.Value, wantCookie.Value)
	}

	if responseCookie.Secure != wantCookie.Secure {
		t.Errorf("responseCookie.Secure = %t, want: %t", responseCookie.Secure, wantCookie.Secure)
	}

	if responseCookie.HttpOnly != wantCookie.HttpOnly {
		t.Errorf("responseCookie.HttpOnly = %t, want: %t", responseCookie.HttpOnly, wantCookie.HttpOnly)
	}

	if responseCookie.Path != wantCookie.Path {
		t.Errorf("responseCookie.Path = %q, want: %q", responseCookie.Path, wantCookie.Path)
	}

	if responseCookie.SameSite != wantCookie.SameSite {
		t.Errorf("responseCookie.SameSite = %q, want: %q", responseCookie.SameSite, wantCookie.SameSite)
	}
}
