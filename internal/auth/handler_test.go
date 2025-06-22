package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
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
			signer := &jwt.StubSigner{}
			cfg := &config.Config{}
			baker := &security.StubBaker{}
			providers := &auth.Providers{
				Cfg:     cfg,
				DB:      nil,
				Hasher:  nil,
				Signer:  signer,
				Mailer:  nil,
				UserSvc: nil,
				Baker:   baker,
				TXMgr:   nil,
			}
			authHandler := auth.NewHandler(svc, providers)

			paramsCtx := web.NewContextWithParams(context.Background(), tt.params)
			req := httptest.NewRequestWithContext(paramsCtx, http.MethodPost, "/auth/register", nil)
			rec := httptest.NewRecorder()
			authHandler.RegisterUser(rec, req)

			gotStatus, wantStatus := rec.Code, tt.code
			if gotStatus != wantStatus {
				t.Errorf("rec.Code = %d, want: %d", gotStatus, wantStatus)
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
			providers := &auth.Providers{
				Cfg:     cfg,
				DB:      nil,
				Hasher:  nil,
				Signer:  signer,
				Mailer:  nil,
				UserSvc: nil,
				Baker:   baker,
				TXMgr:   nil,
			}
			authHandler := auth.NewHandler(svc, providers)

			ctx := web.NewContextWithParams(context.Background(), tc.input)
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", http.NoBody)
			rec := httptest.NewRecorder()
			authHandler.LoginUser(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

		})
	}
}
