package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const verificationPath = "/account/verify"

var (
	ErrNotVerified       = errors.New("email not verified")
	ErrIncorrectPassword = errors.New("incorrect password")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserExists        = errors.New("user already exists")
	ErrInvalidToken      = errors.New("invalid token")
	ErrInvalidSubject    = errors.New("claims.sub is not a string")
)

// Repository defines an interface for managing authentication data.
type Repository interface {
	Verify(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, userID, newPassword string) error
}

// Hasher defines an interface for creating and verifying hashes.
type Hasher interface {
	// Hash takes a plain text and creates a hash of it.
	Hash(plain string) (string, error)

	// Verify takes the plain text and hash then checks them if they match.
	Verify(plain, hashed string) (bool, error)
}

// Signer defines an interface for signing and verifying JWT tokens.
type Signer interface {
	// Sign takes a payload and ttl then returns a signed JWT string or an error.
	Sign(claims map[string]any, ttl time.Duration) (string, error)

	// Verify takes a signed JWT token string and returns the decoded claims or an error.
	Verify(token string) (map[string]any, error)
}

type service struct {
	repo      Repository
	userRepo  user.Repository
	hasher    Hasher
	signer    Signer
	mailer    *email.SMTPMailer
	cfgJWT    *config.JWT
	cfgEmail  *config.Email
	clientURL string
	txManager *db.TxManager
}

var _ Service = (*service)(nil)

type Dependencies struct {
	Repo     Repository
	CfgApp   *config.App
	CfgJWT   *config.JWT
	CfgEmail *config.Email
	Hasher   Hasher
	Mailer   *email.SMTPMailer
	Signer   Signer
	Txmgr    *db.TxManager
	UserRepo user.Repository
}

func NewService(deps *Dependencies) Service {
	return &service{
		repo:      deps.Repo,
		userRepo:  deps.UserRepo,
		hasher:    deps.Hasher,
		mailer:    deps.Mailer,
		signer:    deps.Signer,
		txManager: deps.Txmgr,
		clientURL: deps.CfgApp.ClientURL,
		cfgJWT:    deps.CfgJWT,
		cfgEmail:  deps.CfgEmail,
	}
}

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
		return user.User{}, fmt.Errorf("find user by email: %w", err)
	}

	if existing != nil {
		return user.User{}, ErrUserExists
	}

	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("hash password: %w", err)
	}

	newUser, err := s.userRepo.Create(ctx, user.CreateParams{Email: email, PasswordHash: hash})
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
	claims := map[string]any{
		"sub":     userID,
		"purpose": "verify",
	}
	token, err := s.signer.Sign(claims, s.cfgEmail.VerifyTTL.Duration)
	if err != nil {
		return fmt.Errorf("sign verification token: %w", err)
	}

	url := s.clientURL + verificationPath
	verificationEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Verify your email",
		Title:    "Email verification",
		Template: "verification",
		Link:     url + "?token=" + token,
	}

	go s.sendEmail(verificationEmail)

	return nil
}

func (s *service) ResendVerificationEmail(ctx context.Context, email string) error {
	u, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		const format = "find user by email: %w"

		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(format, ErrUserNotFound)
		}
		return fmt.Errorf(format, err)
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
		return fmt.Errorf("verify token: %w: %v", ErrInvalidToken, err)
	}

	purpose, ok := claims["purpose"].(string)
	if !ok || purpose != "verify" {
		return ErrInvalidToken
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return ErrInvalidSubject
	}

	u, err := s.userRepo.Find(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("find user: %w", err)
	}

	if u.VerifiedAt != nil {
		return nil
	}

	if err := s.repo.Verify(ctx, userID); err != nil {
		const format = "verify user: %w"

		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(format, ErrUserNotFound)
		}

		return fmt.Errorf(format, err)
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
		const format = "find user by email: %w"

		if errors.Is(err, user.ErrNotFound) {
			return nil, fmt.Errorf(format, ErrUserNotFound)
		}

		return nil, fmt.Errorf(format, err)
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

	session, err := s.creatSession(u.ID, params.Email)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	return session, nil
}

func (s *service) creatSession(userID, email string) (*Session, error) {
	jwtConfig := s.cfgJWT
	expiresIn := time.Now().Add(jwtConfig.TTL.Duration).Unix()

	sessClaims := map[string]any{
		"sub":     userID,
		"purpose": "session",
	}
	accessToken, err := s.signer.Sign(sessClaims, jwtConfig.TTL.Duration)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refClaims := map[string]any{
		"sub":     userID,
		"purpose": "refresh",
	}
	refreshToken, err := s.signer.Sign(refClaims, jwtConfig.RefreshTTL.Duration)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	userInfo := &UserInfo{
		ID:    userID,
		Email: email,
	}

	session := &Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    TokenType,
		User:         userInfo,
	}

	return session, nil
}

func (s *service) SendPasswordReset(ctx context.Context, email string) error {
	u, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		const format = "find user by email: %w"

		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(format, ErrUserNotFound)
		}

		return fmt.Errorf(format, err)
	}

	url := s.clientURL + "/account/reset-password"

	claims := map[string]any{
		"sub":     u.ID,
		"purpose": "reset",
	}
	token, err := s.signer.Sign(claims, s.cfgEmail.VerifyTTL.Duration)
	if err != nil {
		return fmt.Errorf("sign password reset token: %w", err)
	}

	resetEmail := &HTMLEmail{
		Address:  email,
		Subject:  "Reset Your Password",
		Title:    "Password Reset",
		Link:     url + "?token=" + token,
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
		const format = "find user: %w"

		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf(format, ErrUserNotFound)
		}

		return fmt.Errorf(format, err)
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

	err = s.repo.ChangePassword(ctx, params.userID, newHash)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	return nil
}

func (s *service) RefreshToken(ctx context.Context, token string) (*Session, error) {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return nil, fmt.Errorf("verify refresh token: %w: %v", ErrInvalidToken, err)
	}

	if purpose, ok := claims["purpose"].(string); !ok || purpose != "refresh" {
		return nil, ErrInvalidToken
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, ErrInvalidSubject
	}

	u, err := s.userRepo.Find(ctx, userID)
	if err != nil {
		const format = "find user: %w"

		if errors.Is(err, user.ErrNotFound) {
			return nil, fmt.Errorf(format, ErrUserNotFound)
		}

		return nil, fmt.Errorf(format, err)
	}

	return s.creatSession(userID, u.Email)
}

type ResetPasswordParams struct {
	Token, Password string
}

func (s *service) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	claims, err := s.signer.Verify(params.Token)
	if err != nil {
		return fmt.Errorf("verify token: %w: %v", ErrInvalidToken, err)
	}

	if purpose, ok := claims["purpose"].(string); !ok || purpose != "reset" {
		return ErrInvalidToken
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return ErrInvalidSubject
	}

	hashed, err := s.hasher.Hash(params.Password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.repo.ChangePassword(ctx, userID, hashed); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	return nil
}
