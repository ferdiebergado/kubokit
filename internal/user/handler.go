package user

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

type Service interface {
	List(ctx context.Context) ([]User, error)
}

type Handler struct {
	svc Service
}

func NewHandler(svc Service) *Handler {
	return &Handler{svc}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.List(r.Context())
	if err != nil {
		web.RespondInternalServerError(w, err)
		return
	}

	payload := newListResponse(users)
	web.RespondOK(w, nil, payload)
}

type UserData struct {
	ID         string          `json:"id,omitempty"`
	Email      string          `json:"email,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	VerifiedAt *time.Time      `json:"verified_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at,omitempty"`
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

type ListResponse struct {
	Users []UserData `json:"users,omitempty"`
}

func newListResponse(users []User) *ListResponse {
	data := make([]UserData, 0, len(users))
	for i := range users {
		tmpUser := transformUser(&users[i])
		data = append(data, *tmpUser)
	}

	return &ListResponse{
		Users: data,
	}
}
