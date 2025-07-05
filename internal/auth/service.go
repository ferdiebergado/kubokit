package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/provider"
	"github.com/ferdiebergado/kubokit/internal/user"
)

var _ AuthService = &Service{}

var (
	ErrUserNotVerified   = errors.New("email not verified")
	ErrUserExists        = errors.New("user already exists")
	ErrIncorrectPassword = errors.New("incorrect password")
)

type AuthRepository interface {
	VerifyUser(ctx context.Context, userID string) error
	ChangeUserPassword(ctx context.Context, email, newPassword string) error
}

type Service struct {
	repo      AuthRepository
	userSvc   user.UserService
	hasher    hash.Hasher
	signer    jwt.Signer
	mailer    email.Mailer
	cfg       *config.Config
	txManager db.TxManager
}

type RegisterUserParams struct {
	Email    string
	Password string
}

func (p *RegisterUserParams) LogValue() slog.Value {
	return slog.AnyValue(nil)
}

type HTMLEmail struct {
	Email, Subject, Title, Template, Payload, URI string
}

func (s *Service) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	u := user.User{}
	email := params.Email
	existing, err := s.userSvc.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return u, err
	}

	if existing != nil {
		return u, ErrUserExists
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return u, fmt.Errorf("hash password: %w", err)
	}

	newUser, err := s.userSvc.CreateUser(ctx, user.CreateUserParams{Email: email, PasswordHash: hash})
	if err != nil {
		return u, err
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

func (s *Service) sendEmail(email *HTMLEmail) {
	slog.Info("Sending email...")

	audience := s.cfg.App.URL + email.URI
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
	if err := s.repo.VerifyUser(ctx, userID); err != nil {
		return err
	}
	return nil
}

type LoginUserParams struct {
	Email    string
	Password string
}

func (p *LoginUserParams) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
	)
}

func (s *Service) LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error) {
	u, err := s.userSvc.FindUserByEmail(ctx, params.Email)
	if err != nil {
		return "", "", err
	}

	if u.VerifiedAt == nil {
		return "", "", ErrUserNotVerified
	}

	ok, err := s.hasher.Verify(params.Password, u.PasswordHash)
	if err != nil {
		return "", "", fmt.Errorf("verify password: %w", err)
	}

	if !ok {
		return "", "", ErrIncorrectPassword
	}

	ttl := s.cfg.JWT.TTL.Duration
	accessToken, err = s.signer.Sign(u.ID, []string{s.cfg.JWT.Issuer}, ttl)
	if err != nil {
		return "", "", fmt.Errorf("sign access token: %w", err)
	}

	refreshTTL := s.cfg.JWT.RefreshTTL.Duration
	refreshToken, err = s.signer.Sign(u.ID, []string{s.cfg.JWT.Issuer}, refreshTTL)
	if err != nil {
		return "", "", fmt.Errorf("sign refresh token: %w", err)
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
	email, currentPassword, newPassword string
}

func (s *Service) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	u, err := s.userSvc.FindUserByEmail(ctx, params.email)
	if err != nil {
		return err
	}

	_, err = s.hasher.Verify(params.currentPassword, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}

	newHash, err := s.hasher.Hash(params.newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	return s.repo.ChangeUserPassword(ctx, u.Email, newHash)
}

func (s *Service) PerformAtomicOperation(ctx context.Context, userID string) error {
	return s.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		// All calls within this func will use the same transaction
		// if err := s.repo.VerifyUser(txCtx, userID); err != nil {
		// 	return err
		// }
		// if err := s.repo.ChangeUserPassword(txCtx, userID, "1"); err != nil {
		// 	return err
		// }
		// If both succeed, the transaction commits. If either fails, it rolls back.
		return nil
	})
}

func NewService(repo AuthRepository, provider *provider.Provider, userSvc user.UserService) *Service {
	return &Service{
		repo:      repo,
		userSvc:   userSvc,
		hasher:    provider.Hasher,
		mailer:    provider.Mailer,
		signer:    provider.Signer,
		cfg:       provider.Cfg,
		txManager: provider.TxMgr,
	}
}
