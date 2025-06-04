package auth_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/app/contract/stub"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_RegisterUser(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(0)
	var tests = []struct {
		name       string
		testUser   user.User
		createFunc func(ctx context.Context, params user.CreateUserParams) (user.User, error)
	}{
		{"Successful registration",
			user.User{
				Model: db.Model{
					ID:        "1",
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email: "abc@example.com",
			},
			func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
				return user.User{
					Model: db.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: "abc@example.com",
				}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authRepo := &auth.StubRepo{}
			userSvc := &user.StubService{
				CreateUserFunc: tt.createFunc,
				FindUserByEmailFunc: func(ctx context.Context, email string) (user.User, error) {
					return user.User{}, nil
				},
			}

			hasher := &stub.Hasher{
				HashFunc: func(_ string) (string, error) {
					return "hashed", nil
				},
			}

			mailer := &stub.Mailer{
				SendHTMLFunc: func(to []string, subject, tmplName string, data map[string]string) error {
					return nil
				},
			}

			signer := &stub.Signer{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "signed", nil
				},
			}

			providers := &auth.Providers{
				Hasher: hasher,
				Mailer: mailer,
				Signer: signer,
			}

			cfg := &config.Config{
				Server: &config.Server{
					URL:  "localhost:8888",
					Port: 8888,
				},
				Email: &config.Email{
					Templates: "../../web/templates",
					Layout:    "layout.html",
					Sender:    "test@example.com",
					VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
				},
			}

			authSvc := auth.NewService(authRepo, userSvc, providers, cfg)
			ctx := context.Background()
			params := auth.RegisterUserParams{
				Email:    "abc@example.com",
				Password: "test",
			}
			newUser, err := authSvc.RegisterUser(ctx, params)
			if err != nil {
				t.Fatal(err)
			}

			wantUser, gotUser := tt.testUser, newUser
			if !reflect.DeepEqual(gotUser, wantUser) {
				t.Errorf("newUser = %+v\nwant: %+v", gotUser, wantUser)
			}
		})
	}
}
