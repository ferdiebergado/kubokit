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

type Session struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	User         *UserInfo
}

type Service interface {
	Register(ctx context.Context, params RegisterParams) (user.User, error)
	Verify(ctx context.Context, token string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	Login(ctx context.Context, params LoginParams) (*Session, error)
	SendPasswordReset(ctx context.Context, email string) error
	ChangePassword(ctx context.Context, params ChangePasswordParams) error
	ResetPassword(ctx context.Context, params ResetPasswordParams) error
	RefreshToken(token string) (*Session, error)
	Logout(token string) error
}

type Handler struct {
	svc       Service
	signer    jwt.Signer
	cfgJWT    *config.JWT
	cfgCookie *config.Cookie
}

type ResetPasswordRequest struct {
	Password        string `json:"password,omitempty" validate:"required"`
	PasswordConfirm string `json:"password_confirm,omitempty" validate:"required,eqfield=Password"`
}

func (r *ResetPasswordRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("password", maskChar),
		slog.String("password_confirm", maskChar),
	)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := web.ParamsFromContext[ResetPasswordRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}
	userID, err := UserFromContext(ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}
	params := ResetPasswordParams{
		UserID:   userID,
		Password: req.Password,
	}
	if err = h.svc.ResetPassword(ctx, params); err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	msg := MsgPasswordResetSuccess
	web.RespondOK[any](w, &msg, nil)
}

type RegisterRequest struct {
	Email           string `json:"email,omitempty" validate:"required,email"`
	Password        string `json:"password,omitempty" validate:"required"`
	PasswordConfirm string `json:"password_confirm,omitempty" validate:"required,eqfield=Password"`
}

func (r *RegisterRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("email", maskChar),
		slog.String("password", maskChar),
		slog.String("password_confirm", maskChar),
	)
}

type RegisterResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := web.ParamsFromContext[RegisterRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	params := RegisterParams{
		Email:    req.Email,
		Password: req.Password,
	}
	user, err := h.svc.Register(ctx, params)
	if err != nil {
		if errors.Is(err, ErrExists) {
			web.RespondConflict(w, err, MsgUserExists, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	msg := MsgRegisterSuccess
	data := &RegisterResponse{
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
	ctx := r.Context()
	req, err := web.ParamsFromContext[VerifyRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	if err := h.svc.Verify(ctx, req.Token); err != nil {
		if errors.Is(err, db.ErrQueryFailed) {
			web.RespondInternalServerError(w, err)
			return
		}

		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	msg := MsgVerifySuccess
	web.RespondOK[any](w, &msg, nil)
}

type ResendVerifyEmailRequest struct {
	Email string `json:"email,omitempty"`
}

func (h *Handler) ResendVerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := web.ParamsFromContext[ResendVerifyEmailRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	if err := h.svc.ResendVerificationEmail(ctx, req.Email); err != nil {
		if errors.Is(err, db.ErrQueryFailed) {
			web.RespondInternalServerError(w, err)
			return
		}

		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	msg := MsgReVerifySuccess
	web.RespondOK[any](w, &msg, nil)
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

type UserInfo struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
	User         *UserInfo `json:"user,omitempty"`
}

func (h *Handler) newRefreshCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     h.cfgCookie.Name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	cookie := h.newRefreshCookie("", -1)
	http.SetCookie(w, cookie)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := web.ParamsFromContext[LoginRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	params := LoginParams(req)
	data, err := h.svc.Login(ctx, params)
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
			web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	refreshCookie := h.newRefreshCookie(data.RefreshToken, int(h.cfgJWT.RefreshTTL.Duration.Seconds()))
	http.SetCookie(w, refreshCookie)

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
		web.RespondUnauthorized(w, errors.New("missing refresh cookie"), MsgInvalidUser, nil)
		return
	}

	data, err := h.svc.RefreshToken(cookie.Value)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
			return
		}

		web.RespondInternalServerError(w, err)
		return
	}

	refreshCookie := h.newRefreshCookie(data.RefreshToken, int(h.cfgJWT.RefreshTTL.Duration.Seconds()))
	http.SetCookie(w, refreshCookie)

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
	ctx := r.Context()
	req, err := web.ParamsFromContext[ForgotPasswordRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, errInvalidParams, MsgInvalidUser, nil)
		return
	}

	if err := h.svc.SendPasswordReset(ctx, req.Email); err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	msg := message.ResetSent
	web.RespondOK[any](w, &msg, nil)
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
	ctx := r.Context()

	userID, err := UserFromContext(ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	if userID == "" {
		web.RespondUnauthorized(w, errors.New("user ID is empty"), MsgInvalidUser, nil)
		return
	}

	req, err := web.ParamsFromContext[ChangePasswordRequest](ctx)
	if err != nil {
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	params := ChangePasswordParams{
		userID:          userID,
		currentPassword: req.CurrentPassword,
		newPassword:     req.NewPassword,
	}

	if err := h.svc.ChangePassword(r.Context(), params); err != nil {
		if errors.Is(err, db.ErrQueryFailed) {
			web.RespondInternalServerError(w, err)
			return
		}
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	msg := MsgSuccessPasswordChanged
	web.RespondOK[any](w, &msg, nil)
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
		web.RespondUnauthorized(w, err, MsgInvalidUser, nil)
		return
	}

	h.clearRefreshCookie(w)

	web.RespondNoContent[any](w, nil, nil)
}

func NewHandler(svc Service, cfgJWT *config.JWT, cfgCookie *config.Cookie) (*Handler, error) {
	if svc == nil {
		return nil, errors.New("service should not be nil")
	}

	if cfgJWT == nil {
		return nil, errors.New("JWT config should not be nil")
	}

	if cfgCookie == nil {
		return nil, errors.New("cookie config should not be nil")
	}

	handler := &Handler{
		svc:       svc,
		cfgJWT:    cfgJWT,
		cfgCookie: cfgCookie,
	}

	return handler, nil
}
