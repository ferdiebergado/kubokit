package email

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/config"
)

type templateMap map[string]*template.Template

type SMTPMailer struct {
	from      string
	pass      string
	host      string
	port      int
	sender    string
	templates templateMap
}

func NewSMTPMailer(smtpCfg *config.SMTP, emailCfg *config.Email) (*SMTPMailer, error) {
	if smtpCfg == nil || emailCfg == nil {
		return nil, errors.New("smtp and email config should not be nil")
	}
	path := emailCfg.Templates
	layoutFile := filepath.Join(path, emailCfg.Layout)
	tmplMap, err := parsePages(path, layoutFile)
	if err != nil {
		return nil, fmt.Errorf("parse pages at path %q and layout file %q: %w", path, layoutFile, err)
	}

	return &SMTPMailer{
		from:      smtpCfg.User,
		pass:      smtpCfg.Password,
		host:      smtpCfg.Host,
		port:      smtpCfg.Port,
		sender:    emailCfg.Sender,
		templates: tmplMap,
	}, nil
}

func (e *SMTPMailer) send(to []string, subject, body, contentType string) error {
	from := e.from
	host := e.host
	auth := smtp.PlainAuth(
		"",
		from,
		e.pass,
		host,
	)

	recipients := strings.Join(to, ", ")
	headers := "From: " + e.sender + "\r\n" +
		"To: " + recipients + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-version: 1.0\r\n" +
		"Content-Type: " + contentType + "; charset=\"UTF-8\"\r\n\r\n"

	message := headers + body
	addr := fmt.Sprintf("%s:%d", host, e.port)

	err := smtp.SendMail(
		addr,
		auth,
		from,
		to,
		[]byte(message),
	)

	if err != nil {
		return fmt.Errorf("sending email from %q to %q: %w", from, to, err)
	}

	slog.Info("Email sent.")
	return nil
}

func (e *SMTPMailer) SendHTML(to []string, subject string, tmplName string, data map[string]string) error {
	tmpl, ok := e.templates[tmplName]
	if !ok {
		return fmt.Errorf("template does not exist: %s", tmplName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("execute email template for subject %q: %w", subject, err)
	}

	if err := e.send(to, subject, buf.String(), "text/html"); err != nil {
		return fmt.Errorf("sending email to %q with subject %q: %w", to, subject, err)
	}

	return nil
}

func (e *SMTPMailer) SendPlain(to []string, subject string, body string) error {
	return e.send(to, subject, body, "text/plain")
}

func parsePages(templateDir, layoutFile string) (templateMap, error) {
	tmplMap := make(templateMap)
	layoutTmpl := template.Must(template.New("layout").ParseFiles(layoutFile))
	err := fs.WalkDir(os.DirFS(templateDir), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk directory %q at path %q: %w", templateDir, path, err)
		}

		const suffix = ".html"
		if !d.IsDir() && strings.HasSuffix(path, suffix) {
			name := strings.TrimPrefix(path, "/")
			name = strings.TrimSuffix(name, suffix)
			tmplMap[name] = template.Must(template.Must(layoutTmpl.Clone()).ParseFiles(filepath.Join(templateDir, path)))
			slog.Debug("parsed page", "path", path, "name", name)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("load pages templates: %w", err)
	}

	return tmplMap, nil
}
