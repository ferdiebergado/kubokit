package email

type Mailer interface {
	SendPlain(to []string, subject string, body string) error
	SendHTML(to []string, subject string, tmplName string, data map[string]string) error
}
