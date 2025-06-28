package app

import (
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func mountUserRoutes(r router.Router, handler *user.Handler, signer jwt.Signer) {
	r.Group("/users", func(gr router.Router) {
		gr.Get("/", handler.ListUsers)
	}, auth.RequireToken(signer))
}

func mountAuthRoutes(r router.Router, handler *auth.Handler, validator validation.Validator, providers *auth.Providers) {
	maxBodySize := providers.Cfg.Server.MaxBodyBytes
	signer := providers.Signer

	r.Group("/auth", func(gr router.Router) {
		gr.Post("/register", handler.RegisterUser,
			middleware.DecodePayload[auth.RegisterUserRequest](maxBodySize),
			middleware.ValidateInput[auth.RegisterUserRequest](validator))
		gr.Post("/login", handler.LoginUser,
			middleware.DecodePayload[auth.UserLoginRequest](maxBodySize),
			middleware.ValidateInput[auth.UserLoginRequest](validator))
		gr.Get("/verify", handler.VerifyEmail, auth.VerifyToken(signer))
		gr.Post("/refresh", handler.RefreshToken)
		gr.Post("/logout", handler.LogoutUser)
		gr.Post("/forgot", handler.ForgotPassword,
			middleware.DecodePayload[auth.ForgotPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ForgotPasswordRequest](validator))
		gr.Post("/reset", handler.ResetPassword,
			auth.VerifyToken(signer),
			middleware.DecodePayload[auth.ResetPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ResetPasswordRequest](validator))
	})
}
