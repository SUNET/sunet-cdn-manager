package cmd

import (
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/spf13/cobra"
)

// upCmd represents the up command
var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Migrate to latest version",
	Long:  `Migrate SQL DB to latest version`,
	RunE: func(_ *cobra.Command, _ []string) error {
		conf, err := config.GetConfig(localViper)
		if err != nil {
			return err
		}

		pgConfig, err := conf.PGConfig()
		if err != nil {
			return err
		}

		err = migrations.Up(cdnLogger, pgConfig)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	migrationsCmd.AddCommand(upCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// upCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// upCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
