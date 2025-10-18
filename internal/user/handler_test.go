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
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestHandler_List(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 10, 18, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		svc            user.Service
		wantStatusCode int
		wantBody       *user.ListResponse
	}{
		{
			name: "success - returns user list",
			svc: &user.StubService{
				ListFunc: func(_ context.Context) ([]user.User, error) {
					return []user.User{
						{
							Model: model.Model{
								ID:        "1",
								Metadata:  []byte(`{"role":"admin"}`),
								CreatedAt: now,
								UpdatedAt: now,
							},
							Email:        "a@example.com",
							PasswordHash: "hash1",
							VerifiedAt:   &now,
						},
						{
							Model: model.Model{
								ID:        "2",
								Metadata:  []byte(`{"role":"user"}`),
								CreatedAt: now,
								UpdatedAt: now,
							},
							Email:        "b@example.com",
							PasswordHash: "hash2",
							VerifiedAt:   nil,
						},
					}, nil
				},
			},
			wantStatusCode: http.StatusOK,
			wantBody: &user.ListResponse{
				Users: []user.UserData{
					{
						ID:         "1",
						Email:      "a@example.com",
						Metadata:   json.RawMessage(`{"role":"admin"}`),
						VerifiedAt: &now,
						CreatedAt:  now,
						UpdatedAt:  now,
					},
					{
						ID:         "2",
						Email:      "b@example.com",
						Metadata:   json.RawMessage(`{"role":"user"}`),
						VerifiedAt: nil,
						CreatedAt:  now,
						UpdatedAt:  now,
					},
				},
			},
		},
		{
			name: "error - service fails",
			svc: &user.StubService{
				ListFunc: func(_ context.Context) ([]user.User, error) {
					return nil, errors.New("db error")
				},
			},
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := user.NewHandler(tt.svc)

			req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
			rec := httptest.NewRecorder()

			h.List(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			gotStatusCode := res.StatusCode
			if gotStatusCode != tt.wantStatusCode {
				t.Fatalf("res.StatusCode = %v, want: %v", gotStatusCode, tt.wantStatusCode)
			}

			wantHeader, gotHeader := web.MimeJSON, res.Header.Get(web.HeaderContentType)
			if gotHeader != wantHeader {
				t.Errorf("res.Header.Get(%q) = %q, want: %q", web.HeaderContentType, gotHeader, wantHeader)
			}

			if tt.wantStatusCode == http.StatusOK {
				var listResponse web.OKResponse[*user.ListResponse]
				if err := json.NewDecoder(res.Body).Decode(&listResponse); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if !reflect.DeepEqual(listResponse.Data, tt.wantBody) {
					t.Errorf("list.Response.Data = %+v, want: %+v", listResponse, tt.wantBody)
				}
			}
		})
	}
}
