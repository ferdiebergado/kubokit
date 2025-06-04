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

	tests := []struct {
		name, email, password string
		registerUserFunc      func(ctx context.Context, params auth.RegisterUserParams) (user.User, error)
		createUserFunc        func(ctx context.Context, params user.CreateUserParams) (user.User, error)
		findUserByEmailFunc   func(ctx context.Context, email string) (user.User, error)
		hashFunc              func(plain string) (string, error)
		sendHTMLFunc          func(to []string, subject, tmplName string, data map[string]string) error
		signFunc              func(subject string, audience []string, duration time.Duration) (string, error)
		wantUser              user.User
		assertFunc            func(t *testing.T, gotUser, wantUser user.User, err error)
	}{
		{
			name:     "Successful Registration",
			email:    "user1@example.com",
			password: "test",
			registerUserFunc: func(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
				return user.User{
					Model: db.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: params.Email,
				}, nil
			},
			createUserFunc: func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
				return user.User{
					Model: db.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: params.Email,
				}, nil
			},
			findUserByEmailFunc: func(ctx context.Context, email string) (user.User, error) {
				return user.User{}, nil
			},
			hashFunc: func(_ string) (string, error) {
				return "hashed", nil
			},
			sendHTMLFunc: func(to []string, subject, tmplName string, data map[string]string) error {
				return nil
			},
			signFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
				return "signed", nil
			},
			wantUser: user.User{
				Model: db.Model{
					ID:        "1",
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email: "user1@example.com",
			},
			assertFunc: func(t *testing.T, gotUser, wantUser user.User, err error) {
				t.Helper()

				if err != nil {
					t.Fatal(err)
				}

				if !reflect.DeepEqual(gotUser, wantUser) {
					t.Errorf("gotUser = %+v\nwant: %+v", gotUser, wantUser)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authRepo := &auth.StubRepo{
				RegisterUserFunc: tt.registerUserFunc,
			}

			userSvc := &user.StubService{
				CreateUserFunc:      tt.createUserFunc,
				FindUserByEmailFunc: tt.findUserByEmailFunc,
			}

			hasher := &stub.Hasher{
				HashFunc: tt.hashFunc,
			}

			mailer := &stub.Mailer{
				SendHTMLFunc: tt.sendHTMLFunc,
			}

			signer := &stub.Signer{
				SignFunc: tt.signFunc,
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
				Email:    tt.email,
				Password: tt.password,
			}
			gotUser, err := authSvc.RegisterUser(ctx, params)
			tt.assertFunc(t, gotUser, tt.wantUser, err)
		})
	}
}
