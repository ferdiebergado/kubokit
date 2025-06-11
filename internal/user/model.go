package user

import (
	"time"

	"github.com/ferdiebergado/kubokit/internal/model"
)

type User struct {
	model.Model

	Email        string
	PasswordHash string
	VerifiedAt   *time.Time
}
