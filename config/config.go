// Package config resolves application configuration at boot time via Viper.
//
// Values resolve with Viper precedence: flag > env var > default. Env var names
// mirror the keys with "." replaced by "_" and uppercased, e.g. "smtp.addr" ->
// SMTP_ADDR, "pdns.api.url" -> PDNS_API_URL, "dsn" -> DSN. There is no env
// prefix, so the names match the historical env vars exactly.
//
// This package is read only at boot; it is not mutated at runtime. The
// runtime-mutable PowerDNS connection lives in package web (pdnsClientHolder),
// so no locking is needed here.
package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config keys (also used as Viper keys and, transformed, as env var names).
const (
	KeyDSN        = "dsn"
	KeySMTPAddr   = "smtp.addr"
	KeySMTPUser   = "smtp.user"
	KeySMTPPass   = "smtp.pass"
	KeyMailFrom   = "mail.from"
	KeyPDNSAPIURL = "pdns.api.url"
	KeyPDNSAPIKey = "pdns.api.key"
)

// DefaultDSN is the fallback database DSN.
const DefaultDSN = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

var (
	v    *viper.Viper
	once sync.Once
)

// setup initializes the private Viper instance: env var binding (key -> env,
// e.g. smtp.addr -> SMTP_ADDR) and built-in defaults. It runs exactly once on
// first use, so package config is usable standalone (not only via package cmd).
func setup() {
	once.Do(func() {
		v = viper.NewWithOptions(viper.KeyDelimiter("."))
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
		v.SetDefault(KeyDSN, DefaultDSN)
	})
}

// BindFlag binds a pflag flag to a config key so an explicit flag value takes
// precedence over env/default. Must be called for every flag from package cmd.
// A nil flag (e.g. a flag-name typo between the String() and Lookup() calls) or
// a bind error panics at startup rather than silently dropping the binding.
func BindFlag(key string, flag *pflag.Flag) {
	setup()
	if flag == nil {
		panic(fmt.Sprintf("config: nil flag for key %q (flag name typo?)", key))
	}
	if err := v.BindPFlag(key, flag); err != nil {
		panic(fmt.Sprintf("config: bind flag %q: %v", key, err))
	}
}

// Resolved accessors (flag > env > default), read at boot.

func DSN() string        { return get(KeyDSN) }
func SMTPAddr() string   { return get(KeySMTPAddr) }
func SMTPUser() string   { return get(KeySMTPUser) }
func SMTPPass() string   { return get(KeySMTPPass) }
func MailFrom() string   { return get(KeyMailFrom) }
func PDNSAPIURL() string { return get(KeyPDNSAPIURL) }
func PDNSAPIKey() string { return get(KeyPDNSAPIKey) }

func get(key string) string {
	setup()
	return v.GetString(key)
}
