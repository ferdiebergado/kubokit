package stub

import "errors"

type Mailer struct {
	SendHTMLFunc func(to []string, subject string, tmplName string, data map[string]string) error
}

func (m *Mailer) SendPlain(to []string, subject string, body string) error {
	panic("not implemented") // TODO: Implement
}

func (m *Mailer) SendHTML(to []string, subject string, tmplName string, data map[string]string) error {
	if m.SendHTMLFunc == nil {
		return errors.New("SendHTML not implemented by stub")
	}
	return m.SendHTMLFunc(to, subject, tmplName, data)
}
