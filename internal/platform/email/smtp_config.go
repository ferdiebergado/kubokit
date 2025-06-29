package email

import (
	"fmt"
	"strconv"

	"github.com/ferdiebergado/kubokit/internal/pkg/env"
)

const (
	envSMTPHost = "SMTP_HOST"
	envSMTPPort = "SMTP_PORT"
	envSMTPUser = "SMTP_USER"
	envSMTPPass = "SMTP_PASS"
)

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
}

func NewSMTPConfig() (*SMTPConfig, error) {
	const errFmt = "get env %q: %w"

	smtpHost, err := env.Env(envSMTPHost)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envSMTPHost, err)
	}

	smtpPortStr, err := env.Env(envSMTPPort)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envSMTPPort, err)
	}

	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return nil, fmt.Errorf("convert smtp port string to int: %w", err)
	}

	smtpUser, err := env.Env(envSMTPUser)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envSMTPUser, err)
	}

	smtpPass, err := env.Env(envSMTPPass)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envSMTPPass, err)
	}

	smtpCfg := &SMTPConfig{
		User:     smtpUser,
		Password: smtpPass,
		Host:     smtpHost,
		Port:     smtpPort,
	}

	return smtpCfg, nil
}
