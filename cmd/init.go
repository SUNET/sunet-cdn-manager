package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
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
	RunE: func(cmd *cobra.Command, _ []string) error {
		conf, err := config.GetConfig(localViper)
		if err != nil {
			return err
		}

		pgConfig, err := conf.PGConfig()
		if err != nil {
			return err
		}

		encryptedSessionCookies, err := cmd.Flags().GetBool("encrypted-session-cookies")
		if err != nil {
			return err
		}

		initPasswordFile, err := cmd.Flags().GetString("init-password-file")
		if err != nil {
			return err
		}

		initPasswordFile = filepath.Clean(initPasswordFile)
		if initPasswordFile == "." {
			return fmt.Errorf("you must supply a filename containing an initial password, see --init-password-file")
		}

		password, err := os.ReadFile(initPasswordFile)
		if err != nil {
			return err
		}

		passwordText := strings.TrimRight(string(password), "\r\n")

		u, err := server.Init(cdnLogger, pgConfig, encryptedSessionCookies, passwordText)
		if err != nil {
			if errors.Is(err, cdnerrors.ErrDatabaseInitialized) {
				fmt.Println("database is already initialized, nothing to do")
				return nil
			}
			return err
		}

		fmt.Printf("database is initialized using password from file '%s'\nuser: '%s'\nencrypted session cookies: %t\n", initPasswordFile, u.Name, encryptedSessionCookies)

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
	initCmd.Flags().BoolP("encrypted-session-cookies", "e", true, "if the initial session cookie key also includes encryption")
	initCmd.Flags().String("init-password-file", "", "file containing initial password used for admin user, trailing newlines are stripped")
}
