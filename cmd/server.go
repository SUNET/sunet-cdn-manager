package cmd

import (
	"github.com/SUNET/sunet-cdn-manager/pkg/server"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the manager server",
	Long: `This runs the manager server which exposes
API endpoints and user interface for managing the SUNET CDN service.`,
	Run: func(cmd *cobra.Command, args []string) {
		server.Run(cdnLogger)
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
}
