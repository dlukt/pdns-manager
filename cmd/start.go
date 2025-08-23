/*
Copyright © 2025 Darko Luketic <info@icod.de>
*/
package cmd

import (
	"fmt"
	"net/http"

	"github.com/dlukt/pdns-manager/auth"
	"github.com/dlukt/pdns-manager/ent"
	"github.com/dlukt/pdns-manager/web"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var (
	dsn string
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the server",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := ent.Open("pgx", dsn)
		if err != nil {
			fmt.Println("database error:", err)
			return
		}
		defer client.Close()
		mux := web.NewHandler(auth.NewService(client))
		fmt.Println("listening on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil && err != http.ErrServerClosed {
			fmt.Println("server error:", err)
		}
	},
}

func init() {
	startCmd.Flags().StringVar(&dsn, "dsn", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable", "database DSN")
	rootCmd.AddCommand(startCmd)
}
