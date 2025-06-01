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
	"github.com/ferdiebergado/kubokit/internal/db"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type stubAuthSvc struct {
	RegisterUserFunc func(ctx context.Context, params auth.RegisterUserParams) (user.User, error)
}

func (s stubAuthSvc) RegisterUser(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
	if s.RegisterUserFunc != nil {
		return s.RegisterUserFunc(ctx, params)
	}
	return user.User{}, nil
}

func (s *stubAuthSvc) VerifyUser(ctx context.Context, token string) error {
	panic("not implemented") // TODO: Implement
}

func (s *stubAuthSvc) LoginUser(ctx context.Context, params auth.LoginUserParams) (accessToken string, refreshToken string, err error) {
	panic("not implemented") // TODO: Implement
}

func (s *stubAuthSvc) SendPasswordReset(email string) {
	panic("not implemented") // TODO: Implement
}

func (s *stubAuthSvc) ResetPassword(ctx context.Context, params auth.ResetPasswordParams) error {
	panic("not implemented") // TODO: Implement
}

type stubSigner struct {
	SignFunc func(subject string, audience []string, duration time.Duration) (string, error)
}

func (s *stubSigner) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	if s.SignFunc != nil {
		return s.SignFunc(subject, audience, duration)
	}
	return "", nil
}

func (s *stubSigner) Verify(tokenString string) (string, error) {
	panic("not implemented") // TODO: Implement
}

func TestAuthHandler_RegisterUser(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	testEmail := "test@example.com"
	testPass := "test"
	u := user.User{
		Model: db.Model{
			ID:        "1",
			CreatedAt: now,
			UpdatedAt: now,
		},
		Email: testEmail,
	}
	svc := &stubAuthSvc{
		RegisterUserFunc: func(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
			return u, nil
		},
	}
	signer := &stubSigner{}
	cfg := config.Config{}
	authHandler := auth.NewHandler(svc, signer, &cfg)
	params := auth.RegisterUserRequest{
		Email:           testEmail,
		Password:        testPass,
		PasswordConfirm: testPass,
	}

	paramsCtx := httpx.NewContextWithParams(ctx, params)
	req := httptest.NewRequestWithContext(paramsCtx, http.MethodPost, "/auth/register", nil)
	rec := httptest.NewRecorder()
	authHandler.RegisterUser(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	wantStatus, gotStatus := http.StatusCreated, res.StatusCode
	if gotStatus != wantStatus {
		t.Errorf("\ngot: %d\nwant %d\n", gotStatus, wantStatus)
	}

	var apiRes httpx.OKResponse[*auth.RegisterUserResponse]
	if err := json.NewDecoder(res.Body).Decode(&apiRes); err != nil {
		t.Fatal(err)
	}

	gotUser := apiRes.Data
	wantUser := &auth.RegisterUserResponse{
		ID:        u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt.Truncate(0),
		UpdatedAt: u.UpdatedAt.Truncate(0),
	}
	if !reflect.DeepEqual(gotUser, wantUser) {
		t.Errorf("\ngot: %+v\nwant: %+v\n", gotUser, wantUser)
	}
}
