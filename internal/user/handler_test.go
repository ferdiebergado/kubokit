package user_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/db"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type stubService struct {
	ListUsersFunc func(ctx context.Context) ([]user.User, error)
}

func (s *stubService) CreateUser(ctx context.Context, params user.CreateUserParams) (user.User, error) {
	panic("not implemented") // TODO: Implement
}

func (s *stubService) ListUsers(ctx context.Context) ([]user.User, error) {
	if s.ListUsersFunc == nil {
		return nil, errors.New("ListUsers not implemented in stub")
	}
	return s.ListUsersFunc(ctx)
}

func (s *stubService) FindUserByEmail(ctx context.Context, email string) (user.User, error) {
	panic("not implemented") // TODO: Implement
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
		ListUsersFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}

	userHandler := user.NewHandler(userService)
	userHandler.ListUsers(rr, req)

	res := rr.Result()
	defer res.Body.Close()

	wantStatus, gotStatus := http.StatusOK, res.StatusCode
	if gotStatus != wantStatus {
		t.Errorf("\nwant: %d\ngot: %d\n", wantStatus, gotStatus)
	}

	var apiRes httpx.OKResponse[*user.ListUsersResponse]
	if err := json.NewDecoder(res.Body).Decode(&apiRes); err != nil {
		t.Fatal(err)
	}

	data := apiRes.Data

	wantLen := len(users)
	gotLen := len(data.Users)
	if wantLen != gotLen {
		t.Errorf("\nwant: %d\ngot: %d\n", wantLen, gotLen)
	}

	wantEmail := users[0].Email
	gotEmail := data.Users[0].Email

	if gotEmail != wantEmail {
		t.Errorf("\nwant: %s\ngot: %s\n", wantEmail, gotEmail)
	}
}
