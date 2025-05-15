package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/ferdiebergado/kubokit/internal/app/contract"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/user"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserNotVerified = errors.New("email not verified")
	ErrUserExists      = errors.New("user already exists")
	ErrInvalidToken    = errors.New("invalid token")
)

type CreateUserParams struct {
	Email        string
	PasswordHash string
}

type repo interface {
	CreateUser(ctx context.Context, params CreateUserParams) (user.User, error)
	FindUserByEmail(ctx context.Context, email string) (user.User, error)
	VerifyUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context) ([]user.User, error)
}

type Providers struct {
	Hasher contract.Hasher
	Signer contract.Signer
	Mailer contract.Mailer
}

type Service struct {
	repo   repo
	hasher contract.Hasher
	signer contract.Signer
	mailer contract.Mailer
	cfg    *config.Options
}

func NewService(userRepo repo, provider *Providers, cfg *config.Options) service {
	return &Service{
		repo:   userRepo,
		hasher: provider.Hasher,
		mailer: provider.Mailer,
		signer: provider.Signer,
		cfg:    cfg,
	}
}

type RegisterUserParams struct {
	Email    string
	Password string
}

func (p *RegisterUserParams) LogValue() slog.Value {
	return slog.AnyValue(nil)
}

type LoginUserParams struct {
	Email    string
	Password string
}

func (p *LoginUserParams) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", "*"),
		slog.String("password", "*"),
	)
}

func (s *Service) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	email := params.Email
	existing, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return user.User{}, err
	}

	if !reflect.DeepEqual(existing, user.User{}) {
		return user.User{}, ErrUserExists
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("hasher hash: %w", err)
	}

	newUser, err := s.repo.CreateUser(ctx, CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return user.User{}, fmt.Errorf("create user %s: %w", email, err)
	}

	go s.sendVerificationEmail(newUser)

	return newUser, nil
}

func (s *Service) sendVerificationEmail(user user.User) {
	slog.Info("Sending verification email...")

	const (
		title   = "Email verification"
		subject = "Verify your email"
	)

	audience := s.cfg.Server.URL + "/auth/verify"
	ttl := s.cfg.Email.VerifyTTL.Duration
	token, err := s.signer.Sign(user.ID, []string{audience}, ttl)
	if err != nil {
		slog.Error("failed to generate token", "reason", err)
		return
	}

	data := map[string]string{
		"Title":  title,
		"Header": subject,
		"Link":   audience + "?token=" + token,
	}
	if err := s.mailer.SendHTML([]string{user.Email}, subject, "verification", data); err != nil {
		slog.Error("failed to send email", "reason", err)
		return
	}
}

func (s *Service) VerifyUser(ctx context.Context, token string) error {
	userID, err := s.signer.Verify(token)
	if err != nil {
		return ErrInvalidToken
	}

	return s.repo.VerifyUser(ctx, userID)
}

func (s *Service) LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error) {
	user, err := s.repo.FindUserByEmail(ctx, params.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrUserNotFound
		}
		return "", "", err
	}

	if user.VerifiedAt == nil {
		return "", "", ErrUserNotVerified
	}

	ok, err := s.hasher.Verify(params.Password, user.PasswordHash)
	if err != nil {
		return "", "", err
	}

	if !ok {
		return "", "", ErrUserNotFound
	}

	ttl := s.cfg.JWT.TTL.Duration
	accessToken, err = s.signer.Sign(user.ID, []string{s.cfg.JWT.Issuer}, ttl)
	if err != nil {
		return "", "", err
	}

	refreshTTL := s.cfg.JWT.RefreshTTL.Duration
	refreshToken, err = s.signer.Sign(user.ID, []string{s.cfg.JWT.Issuer}, refreshTTL)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
