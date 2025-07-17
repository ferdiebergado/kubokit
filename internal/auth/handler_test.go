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
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
			}

			signer := jwt.StubSigner{
				SignFunc: func(subject, fp string, audience []string, duration time.Duration) (string, error) {
					return "1", nil
				},
			}

			provider := &provider.Provider{
				Cfg:    cfg,
				Signer: &signer,
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
		loginFunc         func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken, fingerprint string, err error)
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
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken, fp string, err error) {
				return "test_access_token", "test_refresh_token", "fp", nil
			},
			verifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return &jwt.Claims{UserID: testEmail, FingerprintHash: "fp_hash"}, nil
			},
			gotBody: &web.OKResponse[auth.UserLoginResponse]{},
			wantBody: &web.OKResponse[auth.UserLoginResponse]{
				Message: auth.MsgLoggedIn,
				Data: auth.UserLoginResponse{
					AccessToken:  "test_access_token",
					RefreshToken: "test_refresh_token",
					Fingerprint:  "fp",
					ExpiresIn:    int(defaultDuration),
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
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken, fingerprint string, err error) {
				return "", "", "", auth.ErrUserNotVerified
			},
			verifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return nil, nil
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
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken, fingerprint string, err error) {
				return "", "", "", user.ErrNotFound
			},
			verifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return nil, nil
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
			loginFunc: func(ctx context.Context, params auth.LoginUserParams) (accessToken, refreshToken, fingerprint string, err error) {
				return "", "", "", auth.ErrIncorrectPassword
			},
			verifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return nil, nil
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
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "example.com",
					TTL:        timex.Duration{Duration: defaultDuration},
					RefreshTTL: timex.Duration{Duration: defaultDuration},
				},
			}
			provider := &provider.Provider{
				Cfg:    cfg,
				Signer: signer,
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
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
						return &jwt.Claims{UserID: "123", FingerprintHash: "fp_hash"}, nil
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
			provider: &provider.Provider{
				Cfg: &config.Config{
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
						return &jwt.Claims{UserID: "123", FingerprintHash: "fp_hash"}, nil
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
			provider: &provider.Provider{
				Cfg: &config.Config{
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
						return &jwt.Claims{UserID: "123", FingerprintHash: "fp_hash"}, nil
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
					JWT: &config.JWT{
						JTILength:  8,
						Issuer:     "example.com",
						TTL:        timex.Duration{Duration: defaultDuration},
						RefreshTTL: timex.Duration{Duration: defaultDuration},
					},
				},
				Signer: &jwt.StubSigner{
					VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
						return &jwt.Claims{UserID: "1", FingerprintHash: "fp_hash"}, nil
					},
					SignFunc: func(subject, fp string, audience []string, duration time.Duration) (string, error) {
						return "xyz", nil
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
		JWT: &config.JWT{
			JTILength:  8,
			Issuer:     "test@example.com",
			TTL:        timex.Duration{Duration: defaultDuration},
			RefreshTTL: timex.Duration{Duration: defaultDuration},
		},
	}

	tests := []struct {
		name, refreshToken string
		svc                auth.AuthService
		signer             jwt.Signer
		code               int
		gotBody            any
		wantBody           any
	}{
		{
			name:         "With valid refresh token",
			refreshToken: "refresh_token",
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return &jwt.Claims{UserID: "1", FingerprintHash: "fp_hash"}, nil
				},
				SignFunc: func(subject, fp string, audience []string, duration time.Duration) (string, error) {
					return "access_token", nil
				},
			},
			svc: &auth.StubService{
				RefreshTokenFunc: func(token string) (accessToken, fingerprint string, err error) {
					return "access_token", "fp", nil
				},
			},
			code:    http.StatusOK,
			gotBody: &web.OKResponse[auth.RefreshTokenResponse]{},
			wantBody: &web.OKResponse[auth.RefreshTokenResponse]{
				Message: "Token refreshed.",
				Data: auth.RefreshTokenResponse{
					AccessToken: "access_token",
					Fingerprint: "fp",
				},
			},
		},
		{
			name:    "Missing refresh token",
			svc:     &auth.StubService{},
			code:    http.StatusUnauthorized,
			gotBody: &web.ErrorResponse{},
			wantBody: &web.ErrorResponse{
				Message: message.InvalidUser,
			},
			signer: &jwt.StubSigner{},
		},
		{
			name:         "Expired refresh token",
			refreshToken: "expired_refresh_token",
			signer: &jwt.StubSigner{
				VerifyFunc: func(tokenString string) (*jwt.Claims, error) {
					return nil, errors.New("token is expired")
				},
			},
			svc: &auth.StubService{
				RefreshTokenFunc: func(token string) (accessToken, fp string, err error) {
					return "", "", auth.ErrInvalidToken
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

			provider := &provider.Provider{
				Cfg:    cfg,
				Signer: tc.signer,
			}

			authHandler, err := auth.NewHandler(tc.svc, provider)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", http.NoBody)
			if tc.refreshToken != "" {
				req.Header.Set("Authorization", "Bearer "+tc.refreshToken)
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
