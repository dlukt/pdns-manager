/*
Copyright © 2025 Darko Luketic <info@icod.de>
*/
package cmd

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/config"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/ent/settings"
	"github.com/dlukt/pdns-manager/session"
	"github.com/dlukt/pdns-manager/web"
	"github.com/spf13/cobra"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the server",
	Run: func(cmd *cobra.Command, args []string) {
		var dsn string
		if config.DSN == "" {
			dsn = os.Getenv("DSN")
		} else {
			dsn = config.DSN
		}
		var smtpAddr, smtpUser, smtpPass, mailFrom string
		if config.SMTPAddr == "" {
			smtpAddr = os.Getenv("SMTP_ADDR")
		} else {
			smtpAddr = config.SMTPAddr
		}
		if config.SMTPUser == "" {
			smtpUser = os.Getenv("SMTP_USER")
		} else {
			smtpUser = config.SMTPUser
		}
		if config.SMTPPass == "" {
			smtpPass = os.Getenv("SMTP_PASS")
		} else {
			smtpPass = config.SMTPPass
		}
		if config.MailFrom == "" {
			mailFrom = os.Getenv("MAIL_FROM")
		} else {
			mailFrom = config.MailFrom
		}

		var pdnsURL, pdnsKey string
		if config.PDNSAPIURL == "" {
			pdnsURL = os.Getenv("PDNS_API_URL")
		} else {
			pdnsURL = config.PDNSAPIURL
		}
		if config.PDNSAPIKey == "" {
			pdnsKey = os.Getenv("PDNS_API_KEY")
		} else {
			pdnsKey = config.PDNSAPIKey
		}

		client := openDatabaseConnection(dsn)
		defer client.Close()
		if e := client.Schema.Create(context.Background()); e != nil {
			log.Fatalf("failed creating schema: %v", e)
		}
		if pdnsURL == "" {
			if s, err := client.Settings.Query().Where(settings.KeyEQ("pdns_api_url")).Only(context.Background()); err == nil {
				pdnsURL = s.Value
			}
		}
		if pdnsKey == "" {
			if s, err := client.Settings.Query().Where(settings.KeyEQ("pdns_api_key")).Only(context.Background()); err == nil {
				pdnsKey = s.Value
			}
		}
		config.PDNSAPIURL = pdnsURL
		config.PDNSAPIKey = pdnsKey
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("failed generating session key: %v", err)
		}

		var mailer auth.Mailer = auth.NewLogMailer()
		if config.SMTPAddr != "" && config.MailFrom != "" {
			mailer = auth.NewSMTPMailer(smtpAddr, smtpUser, smtpPass, mailFrom)
		}
		sessions := session.NewStore(key)
		mux := web.NewHandler(client, auth.NewService(client, mailer), sessions)
		fmt.Println("listening on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil && err != http.ErrServerClosed {
			fmt.Println("server error:", err)
		}
	},
}

func init() {
	startCmd.Flags().StringVar(&config.SMTPAddr, "smtp-addr", "", "SMTP server address host:port")
	startCmd.Flags().StringVar(&config.SMTPUser, "smtp-user", "", "SMTP username")
	startCmd.Flags().StringVar(&config.SMTPPass, "smtp-pass", "", "SMTP password")
	startCmd.Flags().StringVar(&config.MailFrom, "mail-from", "", "From email address")
	startCmd.Flags().StringVar(&config.PDNSAPIURL, "pdns-api-url", "", "PowerDNS API URL")
	startCmd.Flags().StringVar(&config.PDNSAPIKey, "pdns-api-key", "", "PowerDNS API Key")
	rootCmd.AddCommand(startCmd)
}

// Open new connection
func openDatabaseConnection(databaseUrl string) *ent.Client {
	db, err := sql.Open("pgx", databaseUrl)
	if err != nil {
		log.Fatal(err)
	}

	// Create an ent.Driver from `db`.
	drv := entsql.OpenDB(dialect.Postgres, db)
	return ent.NewClient(ent.Driver(drv))
}
