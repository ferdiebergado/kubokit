package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/provider"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	maskChar  = "*"
	TokenType = "Bearer"
)

var errInvalidParams = errors.New("invalid request params")

type AuthData struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	User         *UserData
}

type AuthService interface {
	RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error)
	VerifyUser(ctx context.Context, token string) error
	LoginUser(ctx context.Context, params LoginUserParams) (*AuthData, error)
	SendPasswordReset(email string)
	ResetPassword(ctx context.Context, params ResetPasswordParams) error
	RefreshToken(token string) (*AuthData, error)
}

type Handler struct {
	svc    AuthService
	signer jwt.Signer
	cfgJWT *config.JWT
}

type RegisterUserRequest struct {
	Email           string `json:"email,omitempty" validate:"required,email"`
	Password        string `json:"password,omitempty" validate:"required"`
	PasswordConfirm string `json:"password_confirm,omitempty" validate:"required,eqfield=Password"`
}

func (r *RegisterUserRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
		slog.String("password_confirm", maskChar),
	)
}

type RegisterUserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *Handler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[RegisterUserRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := RegisterUserParams{
		Email:    req.Email,
		Password: req.Password,
	}
	user, err := h.svc.RegisterUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			web.RespondConflict(w, err, "User already exists.", nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	msg := "Thank you for registering. A verification link was sent to your email."
	data := &RegisterUserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	web.RespondCreated(w, &msg, data)
}

type VerifyUserRequest struct {
	Token string `json:"token,omitempty" validate:"required"`
}

func (h *Handler) VerifyUser(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[VerifyUserRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	if err := h.svc.VerifyUser(r.Context(), req.Token); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			web.RespondNotFound(w, err, err.Error(), nil)
			return
		}
		web.RespondInternalServerError(w, err)
		return
	}

	msg := "Verification success."
	web.RespondOK(w, &msg, struct{}{})
}

type UserLoginRequest struct {
	Email    string `json:"email,omitempty" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}

func (r *UserLoginRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
	)
}

type UserData struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

type UserLoginResponse struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
	User         *UserData `json:"user,omitempty"`
}

func (h *Handler) LoginUser(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[UserLoginRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := LoginUserParams(req)
	data, err := h.svc.LoginUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrUserNotVerified) {
			msg := MsgNotVerified
			details := map[string]string{
				"error_code": "ACCOUNT_NOT_VERIFIED",
			}
			web.RespondUnauthorized(w, err, msg, details)
			return
		}

		if errors.Is(err, user.ErrNotFound) || errors.Is(err, ErrIncorrectPassword) {
			web.RespondUnauthorized(w, err, message.InvalidUser, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	msg := MsgLoggedIn
	res := &UserLoginResponse{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		TokenType:    data.TokenType,
	}

	web.RespondOK(w, &msg, res)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := extractBearerToken(r.Header.Get("Authorization"))
	if err != nil || token == "" {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	data, err := h.svc.RefreshToken(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			web.RespondUnauthorized(w, err, message.InvalidUser, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	msg := MsgRefreshed
	res := &UserLoginResponse{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		TokenType:    data.TokenType,
	}

	web.RespondOK(w, &msg, res)
}

type ForgotPasswordRequest struct {
	Email string `json:"email,omitempty" validate:"required,email"`
}

func (r *ForgotPasswordRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
	)
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[ForgotPasswordRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, errInvalidParams, message.InvalidUser, nil)
		return
	}

	h.svc.SendPasswordReset(req.Email)
	msg := message.ResetSent
	web.RespondOK(w, &msg, struct{}{})
}

type ResetPasswordRequest struct {
	CurrentPassword string `json:"current_password,omitempty" validate:"required"`
	NewPassword     string `json:"new_password,omitempty" validate:"required"`
	RepeatPassword  string `json:"repeat_password,omitempty" validate:"required,eqfield=NewPassword"`
}

func (r *ResetPasswordRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("current_password", maskChar),
		slog.String("new_password", maskChar),
		slog.String("repeat_password", maskChar),
	)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	email, err := user.FromContext(r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	req, err := web.ParamsFromContext[ResetPasswordRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := ResetPasswordParams{
		email:           email,
		currentPassword: req.CurrentPassword,
		newPassword:     req.NewPassword,
	}

	if err := h.svc.ResetPassword(r.Context(), params); err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	msg := message.ResetSuccess
	web.RespondOK(w, &msg, struct{}{})
}

func NewHandler(svc AuthService, providers *provider.Provider) (*Handler, error) {
	cfg := providers.Cfg
	if cfg == nil {
		return nil, errors.New("config should not be nil")
	}

	cfgJWT := cfg.JWT
	if cfgJWT == nil {
		return nil, errors.New("JWT config should not be nil")
	}

	if providers.Signer == nil {
		return nil, errors.New("signer should not be nil")
	}

	handler := &Handler{
		svc:    svc,
		cfgJWT: cfgJWT,
		signer: providers.Signer,
	}

	return handler, nil
}
