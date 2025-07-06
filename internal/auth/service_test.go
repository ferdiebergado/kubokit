package auth_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/provider"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_RegisterUser(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(0)

	tests := []struct {
		name, email, password string
		registerUserFunc      func(ctx context.Context, params auth.RegisterUserParams) (user.User, error)
		createUserFunc        func(ctx context.Context, params user.CreateUserParams) (user.User, error)
		findUserByEmailFunc   func(ctx context.Context, email string) (*user.User, error)
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
					Model: model.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: params.Email,
				}, nil
			},
			createUserFunc: func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
				return user.User{
					Model: model.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
					},
					Email: params.Email,
				}, nil
			},
			findUserByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
				return nil, nil
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
				Model: model.Model{
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
					t.Errorf("gotUser = %+v, want: %+v", gotUser, wantUser)
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

			hasher := &hash.StubHasher{
				HashFunc: tt.hashFunc,
			}

			mailer := &email.StubMailer{
				SendHTMLFunc: tt.sendHTMLFunc,
			}

			signer := &jwt.StubSigner{
				SignFunc: tt.signFunc,
			}

			cfg := &config.Config{
				App: &config.App{
					URL: "localhost:8888",
				},
				Server: &config.Server{
					Port: 8888,
				},
				Email: &config.Email{
					Templates: "../../web/templates",
					Layout:    "layout.html",
					Sender:    "test@example.com",
					VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
				},
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "localhost:8888",
					TTL:        timex.Duration{Duration: 15 * time.Minute},
					RefreshTTL: timex.Duration{Duration: 24 * time.Hour},
				},
			}
			stubTxMgr := &db.StubTxManager{}
			provider := &provider.Provider{
				Hasher: hasher,
				Mailer: mailer,
				Signer: signer,
				Cfg:    cfg,
				TxMgr:  stubTxMgr,
			}

			authSvc, err := auth.NewService(authRepo, provider, userSvc)
			if err != nil {
				t.Fatal(err)
			}

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
