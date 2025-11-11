package cmd

import (
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/server"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the manager server",
	Long: `This runs the manager server which exposes
API endpoints and user interface for managing the SUNET CDN service.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		devMode, err := cmd.Flags().GetBool("dev")
		if err != nil {
			return err
		}

		disableAcme, err := cmd.Flags().GetBool("disable-acme")
		if err != nil {
			return err
		}

		tlsCertFile, err := cmd.Flags().GetString("tls-cert-file")
		if err != nil {
			return err
		}

		tlsKeyFile, err := cmd.Flags().GetString("tls-key-file")
		if err != nil {
			return err
		}

		shutdownDelay, err := cmd.Flags().GetDuration("shutdown-delay")
		if err != nil {
			return err
		}

		disableDomainVerification, err := cmd.Flags().GetBool("disable-domain-verification")
		if err != nil {
			return err
		}

		err = server.Run(cdnLogger, devMode, shutdownDelay, disableDomainVerification, disableAcme, tlsCertFile, tlsKeyFile)
		if err != nil {
			cdnLogger.Fatal().Err(err).Msg("unable to start")
		}

		return err
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	serverCmd.Flags().Bool("dev", false, "run server in development mode")
	serverCmd.Flags().Bool("disable-acme", false, "disable ACME, reads TLS cert and key from files instead")
	serverCmd.Flags().String("tls-cert-file", "server.crt", "cert file used for TLS if ACME is disabled")
	serverCmd.Flags().String("tls-key-file", "server.key", "key file used for TLS if ACME is disabled")
	serverCmd.Flags().Duration("shutdown-delay", time.Second*5, "how long to wait before stopping http request handling on shutdown")
	serverCmd.Flags().Bool("disable-domain-verification", false, "disable domain verification DNS lookups")
}
