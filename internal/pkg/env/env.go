package env

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/pkg/message"
)

// Loads environment variables from a file
func Load(envFile string) error {
	slog.Info("Loading environment file", "file", envFile)

	file, err := os.Open(envFile)
	if err != nil {
		return fmt.Errorf("open env file %s: %w", envFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comments
		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = line[:commentIdx]
		}

		// Split the line into key and value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			slog.Warn("Invalid line format", "file", envFile, "line", lineNum)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes around value if present
		if len(value) > 1 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		// Set the environment variable
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("os setenv: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	slog.Info("Environment file loaded successfully", "file", envFile)
	return nil
}

func Env(envVar string) (string, error) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf(message.EnvErrFmt, val)
	}
	return val, nil
}
