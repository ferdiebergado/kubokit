package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const verificationPath = "/account/verify"

var (
	ErrNotVerified       = errors.New("email not verified")
	ErrIncorrectPassword = errors.New("incorrect password")
	ErrServiceFailed     = errors.New("auth service was unable to complete the operation")
)

type ServiceError struct {
	Op  string
	Err error
}

func (e *ServiceError) Error() string {
	return e.Op + ": " + e.Err.Error()
}

type Repository interface {
	Verify(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, email, newPassword string) error
}

// Claims represents the JWT claims that are processed for authentication.
type Claims struct {
	UserID string
}

// Signer defines methods for signing and verifying JWT tokens.
type Signer interface {
	Sign(subject string, audience []string, duration time.Duration) (string, error)
	Verify(tokenString string) (*Claims, error)
}

type service struct {
	repo      Repository
	userRepo  user.Repository
	hasher    *security.Argon2Hasher
	signer    Signer
	mailer    *email.SMTPMailer
	cfgJWT    *config.JWT
	cfgEmail  *config.Email
	clientURL string
	txManager db.TxManager
}

type ServiceProvider struct {
	CfgApp   *config.App
	CfgJWT   *config.JWT
	CfgEmail *config.Email
	Hasher   *security.Argon2Hasher
	Mailer   *email.SMTPMailer
	Signer   Signer
	Txmgr    db.TxManager
	UserRepo user.Repository
}

func NewService(repo Repository, provider *ServiceProvider) (Service, error) {
	cfgApp := provider.CfgApp
	if cfgApp == nil {
		return nil, errors.New("app config is required")
	}

	cfgEmail := provider.CfgEmail
	if cfgEmail == nil {
		return nil, errors.New("email config is required")
	}

	cfgJWT := provider.CfgJWT
	if cfgJWT == nil {
		return nil, errors.New("jwt config is required")
	}

	clientURL := cfgApp.ClientURL

	svc := &service{
		repo:      repo,
		userRepo:  provider.UserRepo,
		hasher:    provider.Hasher,
		mailer:    provider.Mailer,
		signer:    provider.Signer,
		txManager: provider.Txmgr,
		clientURL: clientURL,
		cfgJWT:    cfgJWT,
		cfgEmail:  cfgEmail,
	}

	return svc, nil
}

var _ Service = &service{}

type RegisterParams struct {
	Email    string
	Password string
}

func (p *RegisterParams) LogValue() slog.Value {
	return slog.AnyValue(nil)
}

func (s *service) Register(ctx context.Context, params RegisterParams) (user.User, error) {
	email := params.Email
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return user.User{}, fmt.Errorf(MsgFmtFindUserByEmail, err)
	}

	if existing != nil {
		return user.User{}, user.ErrDuplicate
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("hash password: %w", err)
	}

	newUser, err := s.userRepo.Create(ctx, user.CreateParams{Email: email, Password: hash})
	if err != nil {
		return user.User{}, fmt.Errorf("create user: %w", err)
	}

	if err := s.sendVerificationEmail(newUser.Email, newUser.ID); err != nil {
		return user.User{}, fmt.Errorf("send verification email: %w", err)
	}

	return newUser, nil
}

type HTMLEmail struct {
	Address, Subject, Title, Template, Link string
}

func (s *service) sendVerificationEmail(email, userID string) error {
	audience := s.clientURL + verificationPath

	// TODO: add purpose claim
	ttl := s.cfgEmail.VerifyTTL.Duration
	token, err := s.signer.Sign(userID, []string{audience}, ttl)
	if err != nil {
		return fmt.Errorf("sign verification token: %w", err)
	}

	verificationEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Verify your email",
		Title:    "Email verification",
		Template: "verification",
		Link:     audience + "?token=" + token,
	}

	go s.sendEmail(verificationEmail)

	return nil
}

func (s *service) ResendVerificationEmail(ctx context.Context, email string) error {
	u, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(MsgFmtFindUserByEmail, err)
		}
		return &ServiceError{Op: "find user by email", Err: err}
	}

	return s.sendVerificationEmail(u.Email, u.ID)
}

func (s *service) sendEmail(email *HTMLEmail) {
	data := map[string]string{
		"Title":  email.Title,
		"Header": email.Subject,
		"Link":   email.Link,
	}

	slog.Info("Sending email...")
	if err := s.mailer.SendHTML([]string{email.Address}, email.Subject, email.Template, data); err != nil {
		slog.Error("failed to send email", "reason", err)
		return
	}
}

func (s *service) Verify(ctx context.Context, token string) error {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return fmt.Errorf("verify token: %w", err)
	}

	if err := s.repo.Verify(ctx, claims.UserID); err != nil {
		const op = "verify user"

		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, err)
		}

		return &ServiceError{Op: op, Err: err}
	}

	return nil
}

type LoginParams struct {
	Email    string
	Password string
}

func (p *LoginParams) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
	)
}

func (s *service) Login(ctx context.Context, params LoginParams) (*Session, error) {
	u, err := s.userRepo.FindByEmail(ctx, params.Email)
	if err != nil {
		return nil, fmt.Errorf(MsgFmtFindUserByEmail, err)
	}

	if u.VerifiedAt == nil {
		return nil, ErrNotVerified
	}

	ok, err := s.hasher.Verify(params.Password, u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}

	if !ok {
		return nil, ErrIncorrectPassword
	}

	session, err := s.generateToken(u.ID, params.Email)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	return session, nil
}

func (s *service) generateToken(userID, email string) (*Session, error) {
	jwtConfig := s.cfgJWT
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

	userData := &UserInfo{
		ID:    userID,
		Email: email,
	}

	session := &Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    TokenType,
		User:         userData,
	}

	return session, nil
}

func (s *service) SendPasswordReset(ctx context.Context, email string) error {
	_, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf(MsgFmtFindUserByEmail, err)
	}

	resetEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Reset Your Password",
		Title:    "Password Reset",
		Link:     "/auth/reset-password",
		Template: "reset_password",
	}

	go s.sendEmail(resetEmail)

	return nil
}

type ChangePasswordParams struct {
	userID, currentPassword, newPassword string
}

func (s *service) ChangePassword(ctx context.Context, params ChangePasswordParams) error {
	u, err := s.userRepo.Find(ctx, params.userID)
	if err != nil {
		return fmt.Errorf(MsgFmtFindUser, err)
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

	err = s.repo.ChangePassword(ctx, u.Email, newHash)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	return nil
}

func (s *service) PerformAtomicOperation(ctx context.Context, userID string) error {
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

func (s *service) RefreshToken(ctx context.Context, token string) (*Session, error) {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return nil, fmt.Errorf("verify refresh token: %w", err)
	}

	userID := claims.UserID
	u, err := s.userRepo.Find(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf(MsgFmtFindUser, err)
	}

	return s.generateToken(userID, u.Email)
}

func (s *service) Logout(ctx context.Context, token string) error {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return fmt.Errorf("verify access token: %w", err)
	}

	userID := claims.UserID
	_, err = s.userRepo.Find(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(MsgFmtFindUser, err)
		}
		return &ServiceError{Op: "find user", Err: err}
	}

	return nil
}

type ResetPasswordParams struct {
	UserID, Password string
}

func (s *service) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	u, err := s.userRepo.Find(ctx, params.UserID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(MsgFmtFindUser, err)
		}
		return &ServiceError{Op: "find user", Err: err}
	}

	hashed, err := s.hasher.Hash(params.Password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.repo.ChangePassword(ctx, u.Email, hashed); err != nil {
		const op = "change password"
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, err)
		}
		return &ServiceError{Op: op, Err: err}
	}

	return nil
}
