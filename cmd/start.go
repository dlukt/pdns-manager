/*
Copyright © 2025 Darko Luketic <info@icod.de>
*/
package cmd

import (
	"fmt"
	"net/http"

	"github.com/dlukt/pdns-manager/web"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts the server",
	Run: func(cmd *cobra.Command, args []string) {
		mux := web.NewHandler()
		fmt.Println("listening on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil && err != http.ErrServerClosed {
			fmt.Println("server error:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
