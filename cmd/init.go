package cmd

import (
	"fmt"

	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/server"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database",
	Long: `Initialize the database for use by the system, making sure the database structure
is present as well as creating an initial admin user and role for managing the contents.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		conf, err := config.GetConfig()
		if err != nil {
			return err
		}

		pgConfig, err := conf.PGConfig()
		if err != nil {
			return err
		}

		u, err := server.Init(cdnLogger, pgConfig)
		if err != nil {
			return err
		}

		fmt.Printf("database is initialized\nuser: %s\npassword: %s\n", u.Name, u.Password)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
