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

	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestHandler_ListUsers_Success(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	rec := httptest.NewRecorder()

	now := time.Now()
	users := []user.User{
		{
			Model: model.Model{
				ID:        "1",
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "123@test.com",
			PasswordHash: "hash1",
			VerifiedAt:   &now,
		},
		{
			Model: model.Model{
				ID:        "2",
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "abc@test.com",
			PasswordHash: "hash2",
			VerifiedAt:   &now,
		},
	}

	userService := &user.StubService{
		ListFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}
	userHandler := user.NewHandler(userService)
	userHandler.List(rec, req)

	wantStatus, gotStatus := http.StatusOK, rec.Code
	if gotStatus != wantStatus {
		t.Errorf(message.FmtErrStatusCode, gotStatus, wantStatus)
	}

	wantHeader, gotHeader := web.MimeJSON, rec.Header().Get(web.HeaderContentType)
	if gotHeader != wantHeader {
		t.Errorf("rec.Header().Get(%q) = %q, want: %q", web.HeaderContentType, gotHeader, wantHeader)
	}

	var apiRes web.OKResponse[*user.ListResponse]
	if err := json.NewDecoder(rec.Body).Decode(&apiRes); err != nil {
		t.Fatal(err)
	}

	data := apiRes.Data

	wantLen, gotLen := len(users), len(data.Users)
	if gotLen != wantLen {
		t.Errorf("len(data.Users) = %d, want: %d", gotLen, wantLen)
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
			t.Errorf("data.Users[%d] = %+v, want: %+v", i, gotUser, wantUser)
		}
	}
}

func TestHandler_ListUsers_Error(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	rec := httptest.NewRecorder()

	userService := &user.StubService{
		ListFunc: func(_ context.Context) ([]user.User, error) {
			return nil, errors.New("service error")
		},
	}
	userHandler := user.NewHandler(userService)
	userHandler.List(rec, req)

	wantStatus, gotStatus := http.StatusInternalServerError, rec.Code
	if gotStatus != wantStatus {
		t.Errorf(message.FmtErrStatusCode, gotStatus, wantStatus)
	}
}
