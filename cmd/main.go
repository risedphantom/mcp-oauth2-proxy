package main

import (
	"strings"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
	"github.com/risedphantom/mcp-oauth2-proxy/internal/server"
	"github.com/risedphantom/mcp-oauth2-proxy/utils/errors"
	"github.com/risedphantom/mcp-oauth2-proxy/utils/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Flags
const (
	configFlag    = "config"
	logLevelFlag  = "log-level"
	logFormatFlag = "log-format"
)

// Version information (set during build)
var (
	Version   = "1.0.0"
	BuildTime = ""
	GitCommit = ""
)

// Root command
var rootCmd = &cobra.Command{
	Use:   "mcp-oauth2-proxy",
	Short: "MCP OAuth2 Proxy",
	Long: `An HTTP reverse proxy for MCP servers that injects OIDC tokens
obtained via the client credentials flow.`,
	Run: func(c *cobra.Command, args []string) {
		c.HelpFunc()(c, args)
	},
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// Serve command
var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the proxy server",
	SilenceUsage: true,
	Run: func(_ *cobra.Command, _ []string) {
		cfg, err := config.Load(viper.GetString(configFlag))
		errors.DieOnError("Failed to load config: ", err)

		err = server.Run(cfg)
		errors.DieOnError("Failed to start server: ", err)
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(c *cobra.Command, _ []string) {
		c.Printf("MCP OAuth2 Proxy\n")
		c.Printf("  Version:    %s\n", Version)
		if BuildTime != "" {
			c.Printf("  Build Time: %s\n", BuildTime)
		}
		if GitCommit != "" {
			c.Printf("  Git Commit: %s\n", GitCommit)
		}
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

//nolint:errcheck,gochecknoinits // Ignore errors from viper.BindPFlag
func init() {
	viper.SetEnvPrefix("MCP_OAUTH2_PROXY")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// Global flags
	rootCmd.PersistentFlags().String(logLevelFlag, "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL, PANIC)")
	viper.BindPFlag(logLevelFlag, rootCmd.PersistentFlags().Lookup(logLevelFlag))
	rootCmd.PersistentFlags().String(logFormatFlag, "text", "Log format (text, json)")
	viper.BindPFlag(logFormatFlag, rootCmd.PersistentFlags().Lookup(logFormatFlag))

	// Serve command flags
	serveCmd.Flags().String(configFlag, "config.yaml", "Path to config file")
	viper.BindPFlag(configFlag, serveCmd.Flags().Lookup(configFlag))

	// Register commands
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)

	// Initialize logger
	err := log.Init(viper.GetString(logLevelFlag), viper.GetString(logFormatFlag))
	if err != nil {
		panic(err)
	}
}
