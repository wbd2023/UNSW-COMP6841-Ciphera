package commands

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"ciphera/internal/app"
)

var (
	home       string
	passphrase string
	username   string
	relayURL   string

	appCtx *app.Wire
)

// Execute wires dependencies and runs the CLI root.
func Execute() error {
	root := &cobra.Command{
		Use:   "ciphera",
		Short: "End-to-end encrypted chat CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Default home if not provided.
			if home == "" {
				if h, err := os.UserHomeDir(); err == nil {
					home = filepath.Join(h, ".ciphera")
				}
			}

			httpClient := &http.Client{
				Timeout: 15 * time.Second,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   5 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout:   5 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					IdleConnTimeout:       90 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   10,
				},
			}

			cfg := app.Config{
				Home:     home,
				RelayURL: relayURL,
				HTTP:     httpClient,
			}
			var err error
			appCtx, err = app.BuildFromConfig(cfg)
			return err
		},
	}

	// Global flags.
	root.PersistentFlags().StringVar(&home, "home", "", "config directory (default: $HOME/.ciphera)")
	root.PersistentFlags().StringVarP(&passphrase, "passphrase", "p", "", "passphrase to unlock your keys")
	root.PersistentFlags().StringVar(&relayURL, "relay", "", "relay URL, e.g. http://127.0.0.1:8080")

	// Subcommands.
	root.AddCommand(
		initCmd(),
		fingerprintCmd(),
		registerCmd(),
		startSessionCmd(),
		sendCmd(),
		recvCmd(),
	)

	return root.Execute()
}
