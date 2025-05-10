package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/slim/internal/db"
	httpx "github.com/ferdiebergado/slim/internal/http"
	"github.com/ferdiebergado/slim/internal/user"
)

type stubService struct {
	GetAllUsersFunc func(ctx context.Context) ([]user.User, error)
}

func (s *stubService) GetAllUsers(ctx context.Context) ([]user.User, error) {
	return s.GetAllUsersFunc(ctx)
}

func TestHandler_ListUsers(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	rr := httptest.NewRecorder()
	now := time.Now()
	users := []user.User{
		{
			Model: db.Model{
				ID:        "1",
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "123@test.com",
			PasswordHash: "hash1",
			VerifiedAt:   &now,
		},
	}
	userService := &stubService{
		GetAllUsersFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}

	userHandler := user.NewHandler(userService)
	listUsersHandler := http.HandlerFunc(userHandler.ListUsers)

	listUsersHandler.ServeHTTP(rr, req)

	res := rr.Result()
	defer res.Body.Close()

	wantStatus := http.StatusOK
	gotStatus := res.StatusCode
	if gotStatus != wantStatus {
		t.Errorf("user.Handler.ListUsers() = %d, got: %d", wantStatus, gotStatus)
	}

	var apiRes httpx.OKResponse[*user.ListUsersResponse]
	if err := httpx.DecodeJSON(rr.Body.Bytes(), &apiRes); err != nil {
		t.Fatal(err)
	}

	data := apiRes.Data

	wantLen := len(users)
	gotLen := len(data.Users)
	if wantLen != gotLen {
		t.Errorf("user.Handler.ListUsers() = %d, got: %d user(s)", wantLen, gotLen)
	}

	wantEmail := users[0].Email
	gotEmail := data.Users[0].Email

	if gotEmail != wantEmail {
		t.Errorf("user.Handler.ListUsers() = %s, got: %s", wantEmail, gotEmail)
	}
}
