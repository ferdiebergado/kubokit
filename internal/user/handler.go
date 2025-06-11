package user

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ferdiebergado/gopherkit/http/response"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

type UserService interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

type Handler struct {
	Svc UserService
}

func NewHandler(svc UserService) *Handler {
	return &Handler{svc}
}

type UserData struct {
	ID         string          `json:"id,omitempty"`
	Email      string          `json:"email,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	VerifiedAt *time.Time      `json:"verified_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at,omitempty"`
}

type ListUsersResponse struct {
	Users []UserData `json:"users,omitempty"`
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.Svc.ListUsers(r.Context())
	if err != nil {
		response.ServerError(w, err)
		return
	}

	payload := newListUsersResponse(users)
	web.OK(w, http.StatusOK, nil, payload)
}

func transformUser(u *User) *UserData {
	return &UserData{
		ID:         u.ID,
		Email:      u.Email,
		Metadata:   u.Metadata,
		VerifiedAt: u.VerifiedAt,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

func newListUsersResponse(users []User) *ListUsersResponse {
	data := make([]UserData, 0, len(users))
	for i := range users {
		tmpUser := transformUser(&users[i])
		data = append(data, *tmpUser)
	}

	return &ListUsersResponse{
		Users: data,
	}
}
