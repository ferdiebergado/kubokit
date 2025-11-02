package auth_test

import (
	"os"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
)

const (
	mockEmail    = "test@example.com"
	mockPassword = "test"
)

func TestMain(t *testing.M) {
	logging.SetupLogger("testing", "error", os.Stdout)

	code := t.Run()
	os.Exit(code)
}
