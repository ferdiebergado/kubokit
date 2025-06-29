package env

import (
	"fmt"
	"os"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
)

func Env(envVar string) (string, error) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf(message.EnvErrFmt, val)
	}
	return val, nil
}
