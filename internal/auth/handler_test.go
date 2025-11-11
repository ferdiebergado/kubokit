package auth_test

import (
	"context"
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
	cookieName   = "refresh_token"
	maxAge       = 1000
	accessToken  = "mock_access_token"
	refreshToken = "mock_refresh_token"
	mockUserID   = "1"
)

func TestHandler_ForgotPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		svc        auth.Service
		params     *auth.ForgotPasswordRequest
		wantStatus int
		wantBody   map[string]any
	}{
		{
			name: "success",
			params: &auth.ForgotPasswordRequest{
				Email: mockEmail,
			},
			svc: &auth.StubService{
				SendPasswordResetFunc: func(ctx context.Context, email string) error {
					return nil
				},
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgResetSent,
			},
		},
		{
			name:       "no params in context",
			params:     nil,
			svc:        nil,
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "service error",
			params: &auth.ForgotPasswordRequest{
				Email: mockEmail,
			},
			svc: &auth.StubService{
				SendPasswordResetFunc: func(ctx context.Context, email string) error {
					return errors.New("service failed")
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgJWT := &config.JWT{}
			cfgCookie := &config.Cookie{}
			handler := auth.NewHandler(tt.svc, cfgJWT, cfgCookie)
			ctx := t.Context()
			if tt.params != nil {
				ctx = web.NewContextWithParams(ctx, *tt.params)
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/forgot", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ForgotPassword(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}
		})
	}
}

func TestHandler_Register(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
	}{
		{
			name: "user does not exist returns 201 with new user",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{
						Model: model.Model{
							ID:        mockUserID,
							CreatedAt: now,
							UpdatedAt: now,
						},
						Email:        mockEmail,
						PasswordHash: "hashed",
					}, nil
				},
			},
			wantStatus: http.StatusCreated,
			wantBody: map[string]any{
				"message": auth.MsgRegisterSuccess,
				"data": map[string]any{
					"id":         mockUserID,
					"email":      mockEmail,
					"created_at": now.Format(time.RFC3339Nano),
					"updated_at": now.Format(time.RFC3339Nano),
				},
			},
		},
		{
			name: "user exists returns 409",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{}, user.ErrDuplicate
				},
			},
			wantStatus: http.StatusConflict,
			wantBody: map[string]any{
				"message": auth.MsgUserExists,
			},
		},
		{
			name: "service failure returns 500",
			service: &auth.StubService{
				RegisterFunc: func(ctx context.Context, params auth.RegisterParams) (user.User, error) {
					return user.User{}, errors.New("service failed")
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := auth.NewHandler(tt.service, &config.JWT{}, &config.Cookie{})

			mockRequest := auth.RegisterRequest{
				Email:           mockEmail,
				Password:        mockPassword,
				PasswordConfirm: mockPassword,
			}

			ctx := web.NewContextWithParams(context.Background(), mockRequest)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/register", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Register(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}
		})
	}
}

func TestHandler_Login(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
		wantCookie *http.Cookie
	}{
		{
			name: "verified user with correct password returns 200 with session and cookie",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
						ExpiresIn:    maxAge,
						TokenType:    "Bearer",
						User: &auth.UserInfo{
							ID:    mockUserID,
							Email: mockEmail,
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
						"id":    mockUserID,
						"email": mockEmail,
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
			name: "unverified user with correct password returns 401",
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
			name: "user does not exist returns 401",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, auth.ErrUserNotFound
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "verified user with incorrect password returns 401",
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
			name: "service failure returns 500",
			service: &auth.StubService{
				LoginFunc: func(ctx context.Context, params auth.LoginParams) (*auth.Session, error) {
					return &auth.Session{}, errors.New("service failed")
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgJWT := &config.JWT{
				RefreshTTL: timex.Duration{Duration: maxAge * time.Second},
			}
			cfgCookie := &config.Cookie{
				Name: cookieName,
			}

			handler := auth.NewHandler(tt.service, cfgJWT, cfgCookie)

			params := auth.LoginRequest{
				Email:    mockEmail,
				Password: mockPassword,
			}
			ctx := web.NewContextWithParams(context.Background(), params)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Login(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}

			assertCookies(t, res, tt.wantCookie)
		})
	}
}

func TestHandler_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
	}{
		{
			name: "valid verification token returns 200",
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
			name: "invalid verification token returns 401",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return auth.ErrInvalidToken
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "service failure returns 500",
			service: &auth.StubService{
				VerifyFunc: func(ctx context.Context, token string) error {
					return errors.New("service failed")
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := auth.NewHandler(tt.service, &config.JWT{}, &config.Cookie{})

			mockRequest := auth.VerifyRequest{
				Token: "mock_token",
			}
			ctx := web.NewContextWithParams(context.Background(), mockRequest)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/verify", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Verify(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}
		})
	}
}

func TestHandler_ChangePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    auth.Service
		userID     string
		wantStatus int
		wantBody   map[string]any
	}{
		{
			name: "user exists returns 200",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return nil
				},
			},
			userID:     mockUserID,
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgSuccessPasswordChanged,
			},
		},
		{
			name:       "user is not logged-in returns 401",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "user does not exist returns 401",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return auth.ErrUserNotFound
				},
			},
			userID:     mockUserID,
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "incorrect current password returns 401",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return auth.ErrIncorrectPassword
				},
			},
			userID:     mockUserID,
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "service failure returns 500",
			service: &auth.StubService{
				ChangePasswordFunc: func(ctx context.Context, params auth.ChangePasswordParams) error {
					return errors.New("service failed")
				},
			},
			userID:     mockUserID,
			wantStatus: http.StatusInternalServerError,
			wantBody: map[string]any{
				"message": message.UnexpectedErr,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := auth.NewHandler(tt.service, &config.JWT{}, &config.Cookie{})

			params := auth.ChangePasswordRequest{
				CurrentPassword: "mock_current_password",
				NewPassword:     "mock_new_password",
				RepeatPassword:  "mock_new_password",
			}
			ctx := web.NewContextWithParams(context.Background(), params)
			ctx = auth.ContextWithUser(ctx, tt.userID)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/change-password", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ChangePassword(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}
		})
	}
}

func TestHandler_RefreshToken(t *testing.T) {
	t.Parallel()

	const tokenType = "Bearer"

	tests := []struct {
		name          string
		service       auth.Service
		refreshCookie *http.Cookie
		wantStatus    int
		wantBody      map[string]any
		wantCookie    *http.Cookie
	}{
		{
			name: "valid refresh cookie returns ok with new session",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return &auth.Session{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
						ExpiresIn:    maxAge,
						TokenType:    tokenType,
						User: &auth.UserInfo{
							ID:    mockUserID,
							Email: mockEmail,
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
						"id":    mockUserID,
						"email": mockEmail,
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
			name:       "missing refresh cookie returns 401",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name:       "empty refresh cookie value returns 401",
			service:    &auth.StubService{},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
		{
			name: "invalid refresh token returns 401",
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
			name: "user does not exists returns 401",
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
			name: "service failure returns 500",
			service: &auth.StubService{
				RefreshTokenFunc: func(ctx context.Context, token string) (*auth.Session, error) {
					return nil, errors.New("service failed")
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgJWT := &config.JWT{
				RefreshTTL: timex.Duration{Duration: maxAge * time.Second},
			}
			cfgCookie := &config.Cookie{
				Name: cookieName,
			}
			handler := auth.NewHandler(tt.service, cfgJWT, cfgCookie)

			req := httptest.NewRequest(http.MethodPost, "/refresh", http.NoBody)
			if tt.refreshCookie != nil {
				req.AddCookie(tt.refreshCookie)
			}
			rec := httptest.NewRecorder()
			handler.RefreshToken(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want: %v", body, tt.wantBody)
			}

			assertCookies(t, res, tt.wantCookie)
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

	tests := []struct {
		name       string
		userID     string
		wantStatus int
		wantBody   map[string]any
		wantCookie *http.Cookie
	}{
		{
			name:       "user is logged in returns 204 and deletes cookie",
			userID:     "1",
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
			name:       "user is not logged in returns 401",
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgCookie := &config.Cookie{
				Name: cookieName,
			}
			handler := auth.NewHandler(&auth.StubService{}, &config.JWT{}, cfgCookie)

			ctx := context.Background()
			if tt.userID != "" {
				ctx = auth.ContextWithUser(context.Background(), tt.userID)
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/logout", http.NoBody)
			rec := httptest.NewRecorder()
			handler.Logout(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %+v, want: %+v", body, tt.wantBody)
			}

			assertCookies(t, res, tt.wantCookie)
		})
	}
}

func TestHandler_ResetPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    auth.Service
		wantStatus int
		wantBody   map[string]any
	}{
		{
			name: "user exists returns 200",
			service: &auth.StubService{
				ResetPasswordFunc: func(ctx context.Context, params auth.ResetPasswordParams) error {
					return nil
				},
			},
			wantStatus: http.StatusOK,
			wantBody: map[string]any{
				"message": auth.MsgPasswordResetSuccess,
			},
		},
		{
			name: "user does not exist returns 401",
			service: &auth.StubService{
				ResetPasswordFunc: func(ctx context.Context, params auth.ResetPasswordParams) error {
					return auth.ErrUserNotFound
				},
			},
			wantStatus: http.StatusUnauthorized,
			wantBody: map[string]any{
				"message": auth.MsgInvalidUser,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := auth.NewHandler(tt.service, &config.JWT{}, &config.Cookie{})

			params := auth.ResetPasswordRequest{
				Password:        "mock_password",
				PasswordConfirm: "mock_password",
			}

			ctx := web.NewContextWithParams(context.Background(), params)
			ctx = auth.ContextWithUser(ctx, "user1")
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/reset-password", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ResetPassword(rec, req)

			res := rec.Result()
			defer closeBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want: %d", res.StatusCode, tt.wantStatus)
			}

			web.AssertContentType(t, res)

			body := web.DecodeJSONResponse(t, res)
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %+v, want: %+v", body, tt.wantBody)
			}
		})
	}
}

func assertCookies(t *testing.T, res *http.Response, wantCookie *http.Cookie) {
	t.Helper()

	cookies := res.Cookies()
	numCookies := len(cookies)

	if wantCookie != nil {
		if numCookies == 0 {
			t.Fatal("there should be cookies in the response")
		}

		responseCookie := cookies[0]

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
	} else if numCookies > 0 {
		t.Fatal("there should be no cookies in the response")
	}
}

func closeBody(t *testing.T, res *http.Response) {
	t.Helper()

	if err := res.Body.Close(); err != nil {
		t.Logf("failed to close response body: %v", err)
	}
}
