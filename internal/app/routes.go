package app

import (
	"github.com/ferdiebergado/slim/internal/auth"
	"github.com/ferdiebergado/slim/internal/contract"
	"github.com/ferdiebergado/slim/internal/middleware"
	"github.com/ferdiebergado/slim/internal/user"
)

func mountUserRoutes(router contract.Router, handler *user.Handler, signer contract.Signer) {
	router.Get("/users", handler.ListUsers, middleware.RequireAuth(signer))
}

func mountAuthRoutes(router contract.Router, handler *auth.Handler) {
	router.Post("/auth/register", handler.RegisterUser, middleware.ParsePayload[auth.RegisterUserRequest]())
	router.Post("/auth/login", handler.LoginUser, middleware.ParsePayload[auth.UserLoginRequest]())
	router.Get("/auth/verify", handler.VerifyEmail)
}
