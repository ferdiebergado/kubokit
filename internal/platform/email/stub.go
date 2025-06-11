package email

import "errors"

type StubMailer struct {
	SendPlainFunc func(to []string, subject, body string) error
	SendHTMLFunc  func(to []string, subject, tmplName string, data map[string]string) error
}

func (m *StubMailer) SendPlain(to []string, subject, body string) error {
	if m.SendPlainFunc == nil {
		return errors.New("SendPlain not implemented by stub")
	}
	return m.SendPlainFunc(to, subject, body)
}

func (m *StubMailer) SendHTML(to []string, subject, tmplName string, data map[string]string) error {
	if m.SendHTMLFunc == nil {
		return errors.New("SendHTML not implemented by stub")
	}
	return m.SendHTMLFunc(to, subject, tmplName, data)
}
