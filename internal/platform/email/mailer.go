package email

type Mailer interface {
	SendPlain(to []string, subject, body string) error
	SendHTML(to []string, subject, tmplName string, data map[string]string) error
}
