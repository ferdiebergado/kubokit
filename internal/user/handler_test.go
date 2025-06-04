package user_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestHandler_ListUsers_Success(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	rec := httptest.NewRecorder()

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
		{
			Model: db.Model{
				ID:        "2",
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "abc@test.com",
			PasswordHash: "hash2",
			VerifiedAt:   &now,
		},
	}

	userService := &stubService{
		ListUsersFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}
	userHandler := user.NewHandler(userService)
	userHandler.ListUsers(rec, req)

	wantStatus, gotStatus := http.StatusOK, rec.Code
	if gotStatus != wantStatus {
		t.Errorf("rec.Code = %d\nwant: %d", gotStatus, wantStatus)
	}

	var apiRes httpx.OKResponse[*user.ListUsersResponse]
	if err := json.NewDecoder(rec.Body).Decode(&apiRes); err != nil {
		t.Fatal(err)
	}

	data := apiRes.Data

	wantLen, gotLen := len(users), len(data.Users)
	if gotLen != wantLen {
		t.Errorf("len(data.Users) = %d\nwant: %d", gotLen, wantLen)
	}

	for i := range users {
		currentUser := users[i]
		verifiedAt := currentUser.VerifiedAt.Truncate(0)
		wantUser := user.UserData{
			ID:         currentUser.ID,
			Email:      currentUser.Email,
			VerifiedAt: &verifiedAt,
			CreatedAt:  currentUser.CreatedAt.Truncate(0),
			UpdatedAt:  currentUser.UpdatedAt.Truncate(0),
		}
		gotUser := data.Users[i]
		if !reflect.DeepEqual(gotUser, wantUser) {
			t.Errorf("data.Users[%d] = %+v\nwant: %+v", i, gotUser, wantUser)
		}
	}
}

func TestHandler_ListUsers_Error(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	rec := httptest.NewRecorder()

	userService := &stubService{
		ListUsersFunc: func(_ context.Context) ([]user.User, error) {
			return nil, errors.New("service error")
		},
	}
	userHandler := user.NewHandler(userService)
	userHandler.ListUsers(rec, req)

	wantStatus, gotStatus := http.StatusInternalServerError, rec.Code
	if gotStatus != wantStatus {
		t.Errorf("rec.Code = %d\nwant: %d", gotStatus, wantStatus)
	}
}
