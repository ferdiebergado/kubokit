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
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	testEmail = "test@example.com"
	testPass  = "test"
)

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
			name: "service failure",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{}, &auth.ServiceError{Err: errors.New("service failed")}
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
			name: "service failure",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, &auth.ServiceError{Err: errors.New("service failed")}
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

				assertCookies(t, cookies[0], tc.wantCookie)
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
			name: "service failure",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return &auth.ServiceError{Err: errors.New("service failed")}
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
			name: "service failure",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return &auth.ServiceError{Err: errors.New("service failed")}
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

	const (
		accessToken  = "mock_access_token"
		refreshToken = "mock_refresh_token"
		tokenType    = "Bearer"
		maxAge       = 1000
		userID       = "1"
		userEmail    = "abc@example.com"
		cookieName   = "refresh_token"
	)

	type testCase struct {
		name          string
		service       auth.Service
		refreshCookie *http.Cookie
		wantStatus    int
		wantBody      map[string]any
		wantCookie    *http.Cookie
	}

	testCases := []testCase{
		{
			name: "valid refresh cookie",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return &auth.Session{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
						ExpiresIn:    maxAge,
						TokenType:    tokenType,
						User: &auth.UserInfo{
							ID:    userID,
							Email: userEmail,
						},
					}, nil
				},
			},
			refreshCookie: &http.Cookie{
				Name:     cookieName,
				Value:    "current_refresh_token",
				Path:     "/",
				MaxAge:   maxAge,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgRefreshed,
				"data": map[string]any{
					"access_token":  accessToken,
					"refresh_token": refreshToken,
					"token_type":    tokenType,
					"expires_in":    float64(maxAge),
					"user": map[string]any{
						"id":    userID,
						"email": userEmail,
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
			name:       "missing refresh cookie",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name:       "empty refresh cookie value",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "invalid refresh token",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return nil, auth.ErrInvalidToken
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "user does not exists",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return nil, user.ErrNotFound
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "service failure",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return nil, &auth.ServiceError{Err: errors.New("service failed")}
				},
			},
			refreshCookie: &http.Cookie{
				Name:     cookieName,
				Value:    refreshToken,
				Path:     "/",
				MaxAge:   maxAge,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
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
				t.Fatalf("Failed to create auth handler: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/refresh", http.NoBody)
			if tc.refreshCookie != nil {
				req.AddCookie(tc.refreshCookie)
			}
			rec := httptest.NewRecorder()
			handler.RefreshToken(rec, req)

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
					t.Fatal("there should be cookies in the response")
				}
				assertCookies(t, cookies[0], tc.wantCookie)
			} else if numCookies > 0 {
				t.Fatal("there should be no cookies in the response")
			}
		})
	}
}

func TestHandler_Logout(t *testing.T) {
	t.Parallel()

	const (
		cookieName   = "refresh_token"
		accessToken  = "mock_access_token"
		refreshToken = "mock_refresh_token"
	)

	type testCase struct {
		name       string
		service    auth.Service
		params     *auth.LogoutRequest
		wantStatus int
		wantBody   map[string]any
		wantCookie *http.Cookie
	}

	testCases := []testCase{
		{
			name: "valid access token",
			service: &auth.StubService{
				LogoutFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			params: &auth.LogoutRequest{
				AccessToken: accessToken,
			},
			wantStatus: http.StatusNoContent,
			wantBody:   map[string]any{},
			wantCookie: &http.Cookie{
				Name:     cookieName,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			},
		},
		{
			name:       "empty access token",
			service:    &auth.StubService{},
			params:     &auth.LogoutRequest{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "malformed access token",
			service: &auth.StubService{
				LogoutFunc: func(ctx context.Context, token string) error {
					return errors.New("malformed token")
				},
			},
			params: &auth.LogoutRequest{
				AccessToken: accessToken,
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "user does not exists",
			service: &auth.StubService{
				LogoutFunc: func(ctx context.Context, token string) error {
					return user.ErrNotFound
				},
			},
			params: &auth.LogoutRequest{
				AccessToken: accessToken,
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "service failure",
			service: &auth.StubService{
				LogoutFunc: func(ctx context.Context, token string) error {
					return &auth.ServiceError{Err: errors.New("query failed")}
				},
			},
			params: &auth.LogoutRequest{
				AccessToken: accessToken,
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

			cfgCookie := &config.Cookie{
				Name: cookieName,
			}
			handler, err := auth.NewHandler(tc.service, &config.JWT{}, cfgCookie)
			if err != nil {
				t.Fatalf("failed to create auth handler: %v", err)
			}

			ctx := context.Background()
			if tc.params != nil {
				ctx = web.NewContextWithParams(ctx, *tc.params)
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/logout", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Logout(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tc.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tc.wantBody) {
				t.Errorf("body = %+v, want: %+v", body, tc.wantBody)
			}

			cookies := res.Cookies()
			numCookies := len(cookies)
			if tc.wantCookie != nil {
				if numCookies == 0 {
					t.Fatal("there should be cookies in the response")
				}
				assertCookies(t, cookies[0], tc.wantCookie)
			} else if numCookies > 0 {
				t.Fatal("there should be no cookies in the response")
			}
		})
	}
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

func assertCookies(t *testing.T, responseCookie, wantCookie *http.Cookie) {
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
