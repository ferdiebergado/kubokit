package user

import (
	"time"

	"github.com/ferdiebergado/kubokit/internal/db"
)

type User struct {
	db.Model

	Email        string
	PasswordHash string
	VerifiedAt   *time.Time
}
