package auth_test

import (
	"os"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
)

func TestMain(t *testing.M) {
	logging.SetupLogger("testing", "error", os.Stdout)

	code := t.Run()
	os.Exit(code)
}
