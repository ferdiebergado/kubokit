package user

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ferdiebergado/gopherkit/http/response"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
)

type Service interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

type Handler struct {
	Svc Service
}

type userData struct {
	ID         string          `json:"id,omitempty"`
	Email      string          `json:"email,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	VerifiedAt *time.Time      `json:"verified_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at,omitempty"`
}

type ListUsersResponse struct {
	Users []userData `json:"users,omitempty"`
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.Svc.ListUsers(r.Context())
	if err != nil {
		response.ServerError(w, err)
		return
	}

	payload := newListUsersResponse(users)
	httpx.OK(w, http.StatusOK, nil, payload)
}

func transformUser(u User) *userData {
	return &userData{
		ID:         u.ID,
		Email:      u.Email,
		Metadata:   u.Metadata,
		VerifiedAt: u.VerifiedAt,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

func newListUsersResponse(users []User) *ListUsersResponse {
	data := make([]userData, 0, len(users))
	for _, user := range users {
		tmpUser := transformUser(user)
		data = append(data, *tmpUser)
	}

	return &ListUsersResponse{
		Users: data,
	}
}
