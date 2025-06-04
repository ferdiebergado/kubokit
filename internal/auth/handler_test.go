package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/app/contract/stub"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestAuthHandler_RegisterUser(t *testing.T) {
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
	svc := &auth.StubService{
		RegisterUserFunc: func(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
			return u, nil
		},
	}
	signer := &stub.Signer{}
	cfg := &config.Config{}
	authHandler := auth.NewHandler(svc, signer, cfg)
	params := auth.RegisterUserRequest{
		Email:           testEmail,
		Password:        testPass,
		PasswordConfirm: testPass,
	}

	paramsCtx := httpx.NewContextWithParams(context.Background(), params)
	req := httptest.NewRequestWithContext(paramsCtx, http.MethodPost, "/auth/register", nil)
	rec := httptest.NewRecorder()
	authHandler.RegisterUser(rec, req)

	wantStatus, gotStatus := http.StatusCreated, rec.Code
	if gotStatus != wantStatus {
		t.Errorf("rec.Code = %d\nwant: %d\n", gotStatus, wantStatus)
	}

	var apiRes httpx.OKResponse[*auth.RegisterUserResponse]
	if err := json.NewDecoder(rec.Body).Decode(&apiRes); err != nil {
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
		t.Errorf("apiRes.Data = %+v\nwant: %+v\n", gotUser, wantUser)
	}
}
