package app

import (
	"github.com/ferdiebergado/kubokit/internal/app/contract"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/pkg/http/middleware"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func mountUserRoutes(router contract.Router, handler *user.Handler, signer contract.Signer) {
	router.Group("/users", func(r contract.Router) {
		r.Get("/", handler.ListUsers)
	}, auth.RequireToken(signer))
}

func mountAuthRoutes(router contract.Router, handler *auth.Handler, validator contract.Validator, signer contract.Signer, bodySize int64) {
	router.Group("/auth", func(r contract.Router) {
		r.Post("/register", handler.RegisterUser,
			middleware.DecodePayload[auth.RegisterUserRequest](bodySize),
			middleware.ValidateInput[auth.RegisterUserRequest](validator))
		r.Post("/login", handler.LoginUser,
			middleware.DecodePayload[auth.UserLoginRequest](bodySize),
			middleware.ValidateInput[auth.UserLoginRequest](validator))
		r.Get("/verify", handler.VerifyEmail, middleware.VerifyToken(signer))
		r.Post("/refresh", handler.RefreshToken)
		r.Post("/logout", handler.LogoutUser)
		r.Post("/forgot", handler.ForgotPassword,
			middleware.DecodePayload[auth.ForgotPasswordRequest](bodySize),
			middleware.ValidateInput[auth.ForgotPasswordRequest](validator))
		r.Post("/reset", handler.ResetPassword,
			middleware.VerifyToken(signer),
			middleware.DecodePayload[auth.ResetPasswordRequest](bodySize),
			middleware.ValidateInput[auth.ResetPasswordRequest](validator))
	})
}
