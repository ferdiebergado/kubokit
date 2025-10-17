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
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
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
	User         *Data
}

type Service interface {
	Register(ctx context.Context, params RegisterUserParams) (user.User, error)
	Verify(ctx context.Context, token string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	Login(ctx context.Context, params LoginUserParams) (*AuthData, error)
	SendPasswordReset(email string)
	ChangePassword(ctx context.Context, params ChangePasswordParams) error
	ResetPassword(ctx context.Context, params ResetPasswordParams) error
	RefreshToken(token string) (*AuthData, error)
	Logout(token string) error
}

type Handler struct {
	svc             Service
	signer          jwt.Signer
	cfgJWT          *config.JWT
	cfgCookie       *config.Cookie
	cfgCSRF         *config.CSRF
	csrfCookieBaker web.Baker
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

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[RegisterUserRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := RegisterUserParams{
		Email:    req.Email,
		Password: req.Password,
	}
	user, err := h.svc.Register(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrExists) {
			web.RespondConflict(w, err, "User already exists.", nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	msg := MsgRegisterSuccess
	data := &RegisterUserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	web.RespondCreated(w, &msg, data)
}

type VerifyRequest struct {
	Token string `json:"token,omitempty" validate:"required"`
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[VerifyRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	if err := h.svc.Verify(r.Context(), req.Token); err != nil {
		if errors.Is(err, db.ErrQueryFailed) {
			web.RespondInternalServerError(w, err)
			return
		}

		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	msg := MsgVerifySuccess
	web.RespondOK(w, &msg, struct{}{})
}

type ResendVerifyEmailRequest struct {
	Email string `json:"email,omitempty"`
}

func (h *Handler) ResendVerifyEmail(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[ResendVerifyEmailRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	if err := h.svc.ResendVerificationEmail(r.Context(), req.Email); err != nil {
		if errors.Is(err, db.ErrQueryFailed) {
			web.RespondInternalServerError(w, err)
			return
		}

		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	msg := MsgReVerifySuccess
	web.RespondOK(w, &msg, struct{}{})
}

type LoginRequest struct {
	Email    string `json:"email,omitempty" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required"`
}

func (r *LoginRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
	)
}

type Data struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	User         *Data  `json:"user,omitempty"`
}

func (h *Handler) refreshCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     h.cfgCookie.Name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	req, err := web.ParamsFromContext[LoginRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := LoginUserParams(req)
	data, err := h.svc.Login(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrNotVerified) {
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

	refreshCookie := h.refreshCookie(data.RefreshToken, int(h.cfgJWT.RefreshTTL.Duration.Seconds()))
	http.SetCookie(w, refreshCookie)

	csrfCookie, err := h.csrfCookieBaker.Bake()
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	http.SetCookie(w, csrfCookie)

	msg := MsgLoggedIn
	res := &LoginResponse{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		TokenType:    data.TokenType,
		User:         data.User,
	}

	web.RespondOK(w, &msg, res)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfgCookie.Name)

	if err != nil || cookie.Value == "" {
		web.RespondUnauthorized(w, errors.New("missing refresh cookie"), message.InvalidUser, nil)
		return
	}

	data, err := h.svc.RefreshToken(cookie.Value)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			web.RespondUnauthorized(w, err, message.InvalidUser, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	refreshCookie := h.refreshCookie(data.RefreshToken, int(h.cfgJWT.RefreshTTL.Duration.Seconds()))
	http.SetCookie(w, refreshCookie)

	csrfCookie, err := h.csrfCookieBaker.Bake()
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}
	http.SetCookie(w, csrfCookie)

	msg := MsgRefreshed
	res := &LoginResponse{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		TokenType:    data.TokenType,
		User:         data.User,
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

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password,omitempty" validate:"required"`
	NewPassword     string `json:"new_password,omitempty" validate:"required"`
	RepeatPassword  string `json:"repeat_password,omitempty" validate:"required,eqfield=NewPassword"`
}

func (r *ChangePasswordRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("current_password", maskChar),
		slog.String("new_password", maskChar),
		slog.String("repeat_password", maskChar),
	)
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	email, err := user.FromContext(r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	req, err := web.ParamsFromContext[ChangePasswordRequest](r.Context())
	if err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	params := ChangePasswordParams{
		email:           email,
		currentPassword: req.CurrentPassword,
		newPassword:     req.NewPassword,
	}

	if err := h.svc.ChangePassword(r.Context(), params); err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	msg := message.ResetSuccess
	web.RespondOK(w, &msg, struct{}{})
}

type LogoutRequest struct {
	AccessToken string `json:"access_token,omitempty"`
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	params, err := web.ParamsFromContext[LogoutRequest](r.Context())
	if err != nil {
		web.RespondBadRequest(w, err, message.InvalidInput, nil)
		return
	}

	if err = h.svc.Logout(params.AccessToken); err != nil {
		web.RespondUnauthorized(w, err, message.InvalidUser, nil)
		return
	}

	refreshCookie := h.refreshCookie("", -1)
	http.SetCookie(w, refreshCookie)

	csrfCookie := &http.Cookie{
		Name:     h.cfgCSRF.CookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, csrfCookie)

	web.RespondNoContent[any](w, nil, nil)
}

type HandlerProvider struct {
	CfgJWT          *config.JWT
	CfgCookie       *config.Cookie
	CfgCSRF         *config.CSRF
	Signer          jwt.Signer
	CSRFCookieBaker web.Baker
}

func NewHandler(svc Service, provider *HandlerProvider) (*Handler, error) {
	cfgJWT := provider.CfgJWT
	if cfgJWT == nil {
		return nil, errors.New("JWT config should not be nil")
	}

	cfgCookie := provider.CfgCookie
	if cfgCookie == nil {
		return nil, errors.New("cookie config should not be nil")
	}

	cfgCSRF := provider.CfgCSRF
	if cfgCSRF == nil {
		return nil, errors.New("csrf config should not be nil")
	}

	handler := &Handler{
		svc:             svc,
		cfgJWT:          cfgJWT,
		cfgCookie:       cfgCookie,
		cfgCSRF:         cfgCSRF,
		signer:          provider.Signer,
		csrfCookieBaker: provider.CSRFCookieBaker,
	}

	return handler, nil
}
