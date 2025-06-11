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

func mountAuthRoutes(r router.Router, handler *auth.Handler, validator validation.Validator, signer jwt.Signer, bodySize int64) {
	r.Group("/auth", func(gr router.Router) {
		gr.Post("/register", handler.RegisterUser,
			middleware.DecodePayload[auth.RegisterUserRequest](bodySize),
			middleware.ValidateInput[auth.RegisterUserRequest](validator))
		gr.Post("/login", handler.LoginUser,
			middleware.DecodePayload[auth.UserLoginRequest](bodySize),
			middleware.ValidateInput[auth.UserLoginRequest](validator))
		gr.Get("/verify", handler.VerifyEmail, middleware.VerifyToken(signer))
		gr.Post("/refresh", handler.RefreshToken)
		gr.Post("/logout", handler.LogoutUser)
		gr.Post("/forgot", handler.ForgotPassword,
			middleware.DecodePayload[auth.ForgotPasswordRequest](bodySize),
			middleware.ValidateInput[auth.ForgotPasswordRequest](validator))
		gr.Post("/reset", handler.ResetPassword,
			middleware.VerifyToken(signer),
			middleware.DecodePayload[auth.ResetPasswordRequest](bodySize),
			middleware.ValidateInput[auth.ResetPasswordRequest](validator))
	})
}
