package user_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name    string
		repo    user.Repository
		want    []user.User
		wantErr error
	}{
		{
			name: "success - returns users",
			repo: &user.StubRepo{
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
							PasswordHash: "hashed123",
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
							PasswordHash: "hashed456",
							VerifiedAt:   nil,
						},
					}, nil
				},
			},
			want: []user.User{
				{
					Model: model.Model{
						ID:        "1",
						Metadata:  []byte(`{"role":"admin"}`),
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email:        "a@example.com",
					PasswordHash: "hashed123",
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
					PasswordHash: "hashed456",
					VerifiedAt:   nil,
				},
			},
		},
		{
			name: "error - repo fails",
			repo: &user.StubRepo{
				ListFunc: func(_ context.Context) ([]user.User, error) {
					return nil, errors.New("db error")
				},
			},
			wantErr: errors.New("db error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Load("../../config.json")
			if err != nil {
				t.Fatal(err)
			}

			hasher := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)

			svc := user.NewService(tt.repo, hasher)

			got, err := svc.List(ctx)

			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("service.List(ctx) error = %v, wantErr: %v", err, tt.wantErr)
			}

			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Fatalf("service.List(ctx) error = %v, wantErr: %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("service.List(ctx) = %+v, want: %+v", got, tt.want)
			}
		})
	}
}
