package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

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
	cfgJWT    *config.JWT
	cfgEmail  *config.Email
	clientURL string
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
	Address, Subject, Title, Template, Payload, LinkPath string
}

func (s *Service) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	u := user.User{}
	email := params.Email
	existing, err := s.userSvc.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return u, fmt.Errorf("find user by email: %w", err)
	}

	if existing != nil {
		return u, ErrUserExists
	}

	newUser, err := s.userSvc.CreateUser(ctx, user.CreateUserParams{Email: email, Password: params.Password})
	if err != nil {
		return u, fmt.Errorf("create user: %w", err)
	}

	verificationEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Verify your email",
		Title:    "Email verification",
		Template: "verification",
		Payload:  newUser.ID,
		LinkPath: "/auth/verify",
	}

	go s.sendEmail(verificationEmail)

	return newUser, nil
}

func (s *Service) sendEmail(email *HTMLEmail) {
	audience := s.clientURL + "/auth/verify"

	ttl := s.cfgEmail.VerifyTTL.Duration

	token, err := s.signer.Sign(email.Payload, []string{audience}, ttl)

	if err != nil {
		slog.Error("failed to generate verification token", "reason", err)
		return
	}

	data := map[string]string{
		"Title":  email.Title,
		"Header": email.Subject,
		"Link":   audience + "?token=" + token,
	}
	slog.Info("Sending email...")
	if err := s.mailer.SendHTML([]string{email.Address}, email.Subject, email.Template, data); err != nil {
		slog.Error("failed to send email", "reason", err)
		return
	}
}

func (s *Service) VerifyUser(ctx context.Context, token string) error {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return fmt.Errorf("check verification token: %w", err)
	}

	if err := s.repo.VerifyUser(ctx, claims.UserID); err != nil {
		return fmt.Errorf("verify user: %w", err)
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

func (s *Service) LoginUser(ctx context.Context, params LoginUserParams) (*AuthData, error) {
	u, err := s.userSvc.FindUserByEmail(ctx, params.Email)
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	if u.VerifiedAt == nil {
		return nil, ErrUserNotVerified
	}

	ok, err := s.hasher.Verify(params.Password, u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}

	if !ok {
		return nil, ErrIncorrectPassword
	}

	authData, err := s.generateToken(s.cfgJWT, u.ID, params.Email)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	return authData, nil
}

func (s *Service) generateToken(jwtConfig *config.JWT, userID, email string) (*AuthData, error) {
	ttl := time.Now().Add(jwtConfig.TTL.Duration).UnixNano()
	accessToken, err := s.signer.Sign(userID, []string{jwtConfig.Issuer}, time.Duration(ttl))
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshToken, err := s.signer.Sign(userID, []string{jwtConfig.Issuer}, jwtConfig.RefreshTTL.Duration)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	expiresIn := ttl / int64(time.Millisecond)

	userData := &UserData{
		ID:    userID,
		Email: email,
	}

	data := &AuthData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    TokenType,
		User:         userData,
	}

	return data, nil
}

func (s *Service) SendPasswordReset(email string) {
	resetEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Reset Your Password",
		Title:    "Password Reset",
		Payload:  email,
		LinkPath: "/auth/reset",
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
		return fmt.Errorf("find user by email: %w", err)
	}

	ok, err := s.hasher.Verify(params.currentPassword, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}

	if !ok {
		return ErrIncorrectPassword
	}

	newHash, err := s.hasher.Hash(params.newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	err = s.repo.ChangeUserPassword(ctx, u.Email, newHash)
	if err != nil {
		return fmt.Errorf("change user password: %w", err)
	}

	return nil
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

func (s *Service) RefreshToken(token string) (*AuthData, error) {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	userID := claims.UserID
	u, err := s.userSvc.FindUser(context.Background(), userID)
	if err != nil {
		return nil, err
	}

	return s.generateToken(s.cfgJWT, userID, u.Email)
}

func NewService(repo AuthRepository, provider *provider.Provider, userSvc user.UserService) (*Service, error) {
	if provider == nil {
		return nil, errors.New("provider should not be nil")
	}

	if provider.Hasher == nil {
		return nil, errors.New("hasher should not be nil")
	}

	if provider.Mailer == nil {
		return nil, errors.New("mailer should not be nil")
	}

	if provider.Signer == nil {
		return nil, errors.New("signer should not be nil")
	}

	if provider.TxMgr == nil {
		return nil, errors.New("tx manager should not be nil")
	}

	cfg := provider.Cfg
	if cfg == nil {
		return nil, errors.New("config should not be nil")
	}

	if cfg.App == nil {
		return nil, errors.New("app config should not be nil")
	}

	clientURL := cfg.App.ClientURL

	cfgJWT := cfg.JWT

	if cfgJWT == nil {
		return nil, errors.New("jwt config should not be nil")
	}

	cfgEmail := cfg.Email
	if cfgEmail == nil {
		return nil, errors.New("email config should not be nil")
	}

	svc := &Service{
		repo:      repo,
		userSvc:   userSvc,
		hasher:    provider.Hasher,
		mailer:    provider.Mailer,
		signer:    provider.Signer,
		txManager: provider.TxMgr,
		clientURL: clientURL,
		cfgJWT:    cfgJWT,
		cfgEmail:  cfgEmail,
	}

	return svc, nil
}
