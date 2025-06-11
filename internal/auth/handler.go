package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ferdiebergado/gopherkit/http/response"
	"github.com/ferdiebergado/kubokit/internal/config"
	errx "github.com/ferdiebergado/kubokit/internal/pkg/errors"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"

	"github.com/ferdiebergado/kubokit/internal/user"
)

const maskChar = "*"

var errInvalidParams = errors.New("invalid request params")

type AuthService interface {
	RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error)
	VerifyUser(ctx context.Context, token string) error
	LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error)
	SendPasswordReset(email string)
	ResetPassword(ctx context.Context, params ResetPasswordParams) error
}

type Handler struct {
	svc    AuthService
	signer jwt.Signer
	cfg    *config.Config
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
			web.RespondUnprocessableEntity(w, err, "User already exists.", nil)
			return
		}

		if errx.IsContextError(err) {
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

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	userID, err := user.FromContext(r.Context())
	if err != nil {
		web.RespondBadRequest(w, err, message.InvalidInput, nil)
		return
	}

	if err := h.svc.VerifyUser(r.Context(), userID); err != nil {
		response.ServerError(w, err)
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

type UserLoginResponse struct {
	AccessToken string `json:"access_token,omitempty"`
}

func (h *Handler) LoginUser(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[UserLoginRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := LoginUserParams(req)
	accessToken, refreshToken, err := h.svc.LoginUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			web.RespondUnauthorized(w, err, message.InvalidUser, nil)
			return
		}

		if errors.Is(err, ErrUserNotVerified) {
			web.RespondUnauthorized(w, err, message.InvalidUser, nil)
			return
		}

		response.ServerError(w, err)
		return
	}

	cookieCfg := h.cfg.Cookie

	http.SetCookie(w, &http.Cookie{
		Name:     cookieCfg.Name,
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(cookieCfg.MaxAge.Seconds()),
	})

	msg := "Logged in."
	data := &UserLoginResponse{
		AccessToken: accessToken,
	}
	web.RespondOK(w, &msg, data)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Cookie.Name)
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	userID, err := h.signer.Verify(cookie.Value)
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	ttl := h.cfg.JWT.TTL.Duration
	newAccessToken, err := h.signer.Sign(userID, []string{h.cfg.JWT.Issuer}, ttl)
	if err != nil {
		response.ServerError(w, err)
		return
	}

	msg := "Logged in."
	data := &UserLoginResponse{
		AccessToken: newAccessToken,
	}
	web.RespondOK(w, &msg, data)
}

func (h *Handler) LogoutUser(w http.ResponseWriter, r *http.Request) {
	cookieName := h.cfg.Cookie.Name
	if _, err := r.Cookie(cookieName); err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	msg := "Logged out."
	web.RespondOK(w, &msg, struct{}{})
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
		email:       email,
		oldPassword: req.CurrentPassword,
		newPassword: req.NewPassword,
	}

	if err := h.svc.ResetPassword(r.Context(), params); err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	msg := message.ResetSuccess
	web.RespondOK(w, &msg, struct{}{})
}

func NewHandler(userSvc AuthService, signer jwt.Signer, cfg *config.Config) *Handler {
	return &Handler{
		svc:    userSvc,
		signer: signer,
		cfg:    cfg,
	}
}
