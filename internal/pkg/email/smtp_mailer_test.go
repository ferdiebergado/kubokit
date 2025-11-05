package email_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
)

func TestSMTPMailer_SendHTML(t *testing.T) {
	t.Parallel()

	const rootPath = "../../../"

	logging.SetupLogger("testing", "error", os.Stdout)

	if err := env.Load(rootPath + ".env.testing"); err != nil {
		t.Fatalf("failed to load environment: %v", err)
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		t.Fatalf("failed to convert port: %v", err)
	}

	user := os.Getenv("SMTP_USER")
	smtpCfg := &config.SMTP{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     port,
		User:     user,
		Password: os.Getenv("STMP_PASS"),
	}

	emailCfg := &config.Email{
		Templates: rootPath + "web/templates",
		Layout:    "layout.html",
		Sender:    user,
	}
	mailer, err := email.NewSMTPMailer(smtpCfg, emailCfg)
	if err != nil {
		t.Fatalf("failed to create smtp mailer: %v", err)
	}

	to := []string{"test@example.com"}
	subj := "test"
	tmpl := "verification"
	if err := mailer.SendHTML(to, subj, tmpl, nil); err != nil {
		t.Errorf("mailer.SendHTML(%v, %q, %q, %v) = %v, want: %v", to, subj, tmpl, nil, err, nil)
	}
}
