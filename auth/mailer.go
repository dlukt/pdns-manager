package auth

import (
	"fmt"
	"net/smtp"
	"strings"
)

type Mailer interface {
	SendMail(to, subject, body string) error
}

type SMTPMailer struct {
	addr string
	from string
	auth smtp.Auth
}

func NewSMTPMailer(addr, username, password, from string) *SMTPMailer {
	host := strings.Split(addr, ":")[0]
	auth := smtp.PlainAuth("", username, password, host)
	return &SMTPMailer{addr: addr, from: from, auth: auth}
}

func (m *SMTPMailer) SendMail(to, subject, body string) error {
	msg := "From: " + m.from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" + body
	return smtp.SendMail(m.addr, m.auth, m.from, []string{to}, []byte(msg))
}

type logMailer struct{}

func NewLogMailer() Mailer { return logMailer{} }

func (logMailer) SendMail(to, subject, body string) error {
	fmt.Printf("send mail to %s subject %s: %s\n", to, subject, body)
	return nil
}
