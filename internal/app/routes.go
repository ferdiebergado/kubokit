package app

import (
	"github.com/ferdiebergado/kubokit/internal/app/contract"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/pkg/http/middleware"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func mountUserRoutes(router contract.Router, handler *user.Handler, signer contract.Signer) {
	router.Get("/users", handler.ListUsers, middleware.RequireAuth(signer))
}

func mountAuthRoutes(router contract.Router, handler *auth.Handler, validator contract.Validator, bodySize int64) {
	router.Group("/auth", func(r contract.Router) {
		r.Post("/register", handler.RegisterUser,
			middleware.DecodePayload[auth.RegisterUserRequest](bodySize),
			middleware.ValidateInput[auth.RegisterUserRequest](validator))
		r.Post("/login", handler.LoginUser,
			middleware.DecodePayload[auth.UserLoginRequest](bodySize),
			middleware.ValidateInput[auth.UserLoginRequest](validator))
		r.Get("/verify", handler.VerifyEmail)
		r.Post("/refresh", handler.RefreshToken)
		r.Post("/logout", handler.LogoutUser)
	})
}
