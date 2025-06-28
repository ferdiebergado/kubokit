package email_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
)

func TestSMTPMailer_SendHTML(t *testing.T) {
	t.Parallel()
	const rootPath = "../../../"
	if err := env.Load(rootPath + ".env.testing"); err != nil {
		t.Fatal(err)
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		t.Fatal(err)
	}

	user := os.Getenv("SMTP_USER")
	smtpCfg := &email.SMTPConfig{
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
		t.Fatal(err)
	}

	to := []string{"test@example.com"}
	subj := "test"
	tmpl := "verification"
	var data map[string]string
	if err := mailer.SendHTML(to, subj, tmpl, data); err != nil {
		t.Errorf("mailer.SendHTML(%v, %q, %q, %v) = %v, want: %v", to, subj, tmpl, data, err, nil)
	}
}
