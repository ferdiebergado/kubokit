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

var _ AuthService = &Service{}

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserNotVerified = errors.New("email not verified")
	ErrUserExists      = errors.New("user already exists")
)

type AuthRepository interface {
	VerifyUser(ctx context.Context, userID string) error
	ChangeUserPassword(ctx context.Context, email, newPassword string) error
}

type Providers struct {
	Hasher contract.Hasher
	Signer contract.Signer
	Mailer contract.Mailer
}

type Service struct {
	repo    AuthRepository
	userSvc user.UserService
	hasher  contract.Hasher
	signer  contract.Signer
	mailer  contract.Mailer
	cfg     *config.Config
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
	u := user.User{}
	email := params.Email
	existing, err := s.userSvc.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return u, err
	}

	// TODO: Refactor checking of existing user
	if !reflect.DeepEqual(existing, u) {
		return u, ErrUserExists
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return u, fmt.Errorf("hasher hash: %w", err)
	}

	newUser, err := s.userSvc.CreateUser(ctx, user.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return u, fmt.Errorf("create user %s: %w", email, err)
	}

	verifyEmail := &HTMLEmail{
		Email:    newUser.Email,
		Subject:  "Verify your email",
		Title:    "Email verification",
		Template: "verification",
		Payload:  newUser.ID,
		URI:      "/auth/verify",
	}
	go s.sendEmail(verifyEmail)

	return newUser, nil
}

type HTMLEmail struct {
	Email, Subject, Title, Template, Payload, URI string
}

func (s *Service) sendEmail(email *HTMLEmail) {
	slog.Info("Sending email...")

	audience := s.cfg.Server.URL + email.URI
	ttl := s.cfg.Email.VerifyTTL.Duration
	token, err := s.signer.Sign(email.Payload, []string{audience}, ttl)
	if err != nil {
		slog.Error("failed to generate token", "reason", err)
		return
	}

	data := map[string]string{
		"Title":  email.Title,
		"Header": email.Subject,
		"Link":   audience + "?token=" + token,
	}
	if err := s.mailer.SendHTML([]string{email.Email}, email.Subject, email.Template, data); err != nil {
		slog.Error("failed to send email", "reason", err)
		return
	}
}

func (s *Service) VerifyUser(ctx context.Context, userID string) error {
	return s.repo.VerifyUser(ctx, userID)
}

func (s *Service) LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error) {
	user, err := s.userSvc.FindUserByEmail(ctx, params.Email)
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

func (s *Service) SendPasswordReset(email string) {
	resetEmail := &HTMLEmail{
		Email:    email,
		Subject:  "Reset Your Password",
		Title:    "Password Reset",
		Payload:  email,
		URI:      "/auth/reset",
		Template: "reset_password",
	}

	go s.sendEmail(resetEmail)
}

type ResetPasswordParams struct {
	email, oldPassword, newPassword string
}

func (s *Service) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	u, err := s.userSvc.FindUserByEmail(ctx, params.email)
	if err != nil {
		return err
	}

	_, err = s.hasher.Verify(params.oldPassword, u.PasswordHash)
	if err != nil {
		return err
	}

	newHash, err := s.hasher.Hash(params.newPassword)
	if err != nil {
		return err
	}

	return s.repo.ChangeUserPassword(ctx, u.Email, newHash)
}

func NewService(repo AuthRepository, userSvc user.UserService, provider *Providers, cfg *config.Config) *Service {
	return &Service{
		repo:    repo,
		userSvc: userSvc,
		hasher:  provider.Hasher,
		mailer:  provider.Mailer,
		signer:  provider.Signer,
		cfg:     cfg,
	}
}
