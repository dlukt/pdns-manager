/*
Copyright © 2025 Darko Luketic <info@icod.de>
*/
package cmd

import (
	"fmt"
	"net/http"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/config"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/web"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the server",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := ent.Open("pgx", config.DSN)
		if err != nil {
			fmt.Println("database error:", err)
			return
		}
		defer client.Close()
		var mailer auth.Mailer = auth.NewLogMailer()
		if config.SMTPAddr != "" && config.MailFrom != "" {
			mailer = auth.NewSMTPMailer(config.SMTPAddr, config.SMTPUser, config.SMTPPass, config.MailFrom)
		}
		mux := web.NewHandler(auth.NewService(client, mailer))
		fmt.Println("listening on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil && err != http.ErrServerClosed {
			fmt.Println("server error:", err)
		}
	},
}

func init() {
	startCmd.Flags().StringVar(&config.DSN, "dsn", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable", "database DSN")
	startCmd.Flags().StringVar(&config.SMTPAddr, "smtp-addr", "", "SMTP server address host:port")
	startCmd.Flags().StringVar(&config.SMTPUser, "smtp-user", "", "SMTP username")
	startCmd.Flags().StringVar(&config.SMTPPass, "smtp-pass", "", "SMTP password")
	startCmd.Flags().StringVar(&config.MailFrom, "mail-from", "", "From email address")
	rootCmd.AddCommand(startCmd)
}
