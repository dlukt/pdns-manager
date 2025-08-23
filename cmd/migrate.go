/*
Copyright © 2025 Darko Luketic <info@icod.de>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	atlas "ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/dlukt/pdns-manager/config"
	"github.com/dlukt/pdns-manager/ent/migrate"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
)

const migrationsDir = "ent/migrate/migrations"

// migrateCmd generates named migration files using Atlas.
var migrateCmd = &cobra.Command{
	Use:   "migrate [name]",
	Short: "generate a named database migration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		if err := os.MkdirAll(migrationsDir, 0o755); err != nil {
			return fmt.Errorf("creating migration directory: %w", err)
		}
		d, err := atlas.NewLocalDir(migrationsDir)
		if err != nil {
			return fmt.Errorf("creating atlas migration directory: %w", err)
		}
		opts := []schema.MigrateOption{
			schema.WithDir(d),
			schema.WithMigrationMode(schema.ModeReplay),
			schema.WithDialect(dialect.Postgres),
			schema.WithFormatter(atlas.DefaultFormatter),
		}
		dsn := os.Getenv("DSN")
		if dsn == "" {
			dsn = config.DSN
		}
		if err := migrate.NamedDiff(ctx, dsn, args[0], opts...); err != nil {
			return fmt.Errorf("generating migration: %w", err)
		}
		fmt.Printf("generated migration %s\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
