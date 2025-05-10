package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ferdiebergado/gopherkit/http/response"
	"github.com/ferdiebergado/slim/internal/config"
	contextx "github.com/ferdiebergado/slim/internal/context"
	"github.com/ferdiebergado/slim/internal/contract"
	errx "github.com/ferdiebergado/slim/internal/error"
	httpx "github.com/ferdiebergado/slim/internal/http"

	"github.com/ferdiebergado/slim/internal/user"
)

const maskChar = "*"

type service interface {
	RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error)
	VerifyUser(ctx context.Context, token string) error
	LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error)
}

type Handler struct {
	service service
	signer  contract.Signer
	cfg     *config.Options
}

func NewHandler(userService service, signer contract.Signer, cfg *config.Options) *Handler {
	return &Handler{
		service: userService,
		signer:  signer,
		cfg:     cfg,
	}
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
	req, _ := contextx.ParamsFromContext[RegisterUserRequest](r.Context())
	params := RegisterUserParams{
		Email:    req.Email,
		Password: req.Password,
	}
	user, err := h.service.RegisterUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			httpx.Fail(w, http.StatusUnprocessableEntity, err, "User already exists.")
			return
		}

		if errx.IsContextError(err) {
			return
		}

		response.ServerError(w, err)
		return
	}

	data := &RegisterUserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	msg := "Thank you for registering. A verification link was sent to your email."
	httpx.OK(w, http.StatusCreated, &msg, data)
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if token == "" {
		httpx.Fail(w, http.StatusBadRequest, ErrInvalidToken, "Invalid credentials.")
		return
	}

	if err := h.service.VerifyUser(r.Context(), token); err != nil {
		if errors.Is(err, ErrInvalidToken) {
			httpx.Fail(w, http.StatusBadRequest, ErrInvalidToken, "Invalid credentials.")
			return
		}
		response.ServerError(w, err)
		return
	}

	msg := "Verification success."
	httpx.OK[any](w, http.StatusOK, &msg, nil)
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
	req, _ := contextx.ParamsFromContext[UserLoginRequest](r.Context())
	params := LoginUserParams{
		Email:    req.Email,
		Password: req.Password,
	}
	accessToken, refreshToken, err := h.service.LoginUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			httpx.Fail(w, http.StatusUnauthorized, err, "Invalid username/password.")
			return
		}

		if errors.Is(err, ErrUserNotVerified) {
			httpx.Fail(w, http.StatusUnauthorized, err, "Invalid username/password.")
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

	msg := "Registration successful!"
	data := &UserLoginResponse{
		AccessToken: accessToken,
	}
	httpx.OK(w, http.StatusOK, &msg, data)
}

func (h *Handler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Cookie.Name)
	if err != nil {
		httpx.Fail(w, http.StatusUnauthorized, err, "Invalid credentials.")
		return
	}

	userID, err := h.signer.Verify(cookie.Value)
	if err != nil {
		httpx.Fail(w, http.StatusUnauthorized, err, "Invalid credentials.")
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
	httpx.OK(w, http.StatusOK, &msg, data)
}

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookieName := h.cfg.Cookie.Name
	_, err := r.Cookie(cookieName)
	if err != nil {
		response.ServerError(w, err)
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
	httpx.OK[any](w, http.StatusOK, &msg, nil)
}
