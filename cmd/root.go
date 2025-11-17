package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	cdnLogger  zerolog.Logger
	localViper *viper.Viper
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "sunet-cdn-manager",
	SilenceUsage: true,
	Short:        "Management system for SUNET CDN",
	Long: `This is the management system where users of SUNET CDN manage
their cache rules etc.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(logger zerolog.Logger) {
	cdnLogger = logger
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sunet-cdn-manager.toml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// We have config such as [acmedns."manager-test.cdn.sunet.se"]
	// where the expected key is "manager-test.cdn.sunet.se". With the
	// default viper delimiter of "." the key instead becomes just
	// "manager-test".
	//
	// Solution to change delimiter found via
	// https://github.com/spf13/viper/issues/1074, using "::" inspired by
	// README at https://github.com/spf13/viper
	localViper = viper.NewWithOptions(viper.KeyDelimiter("::"))

	if cfgFile != "" {
		// Use config file from the flag.
		localViper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".sunet-cdn-manager" (without extension).
		localViper.AddConfigPath(home)
		localViper.SetConfigType("toml")
		localViper.SetConfigName(".sunet-cdn-manager")
	}

	localViper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := localViper.ReadInConfig(); err == nil {
		cdnLogger.Info().Str("filename", localViper.ConfigFileUsed()).Msg("using config file")
	} else {
		cdnLogger.Fatal().Err(err).Str("filename", localViper.ConfigFileUsed()).Msg("unable to read config file")
	}
}
