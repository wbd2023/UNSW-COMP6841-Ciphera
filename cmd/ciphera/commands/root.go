package commands

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"ciphera/internal/app"
)

var (
	// These flags are shared across all commands.
	homeDir    string
	relayURL   string
	username   string
	passphrase string

	// appCtx holds the wired dependencies after PersistentPreRunE.
	appCtx *app.Wire
)

// Execute initialises the application context and runs the root cobra command.
func Execute() error {
	root := &cobra.Command{
		Use:   "ciphera",
		Short: "End-to-end encrypted chat CLI",
		// Before any sub-command runs we need to build out our Wire (dependencies).
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Default home directory to $HOME/.ciphera if not provided.
			if homeDir == "" {
				if h, err := os.UserHomeDir(); err == nil {
					homeDir = filepath.Join(h, ".ciphera")
				}
			}
			// Ensure the config directory exists (0700).
			if err := os.MkdirAll(homeDir, 0o700); err != nil {
				return fmt.Errorf("creating config dir: %w", err)
			}

			// Construct an HTTP client with sensible timeouts and connection pooling.
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
				HomeDir:    homeDir,
				RelayURL:   relayURL,
				HTTPClient: httpClient,
			}
			var err error
			appCtx, err = app.NewWire(cfg)
			if err != nil {
				return fmt.Errorf("initialising application: %w", err)
			}
			return nil
		},
	}

	// Global flags.
	root.PersistentFlags().StringVar(
		&homeDir,
		"home",
		"",
		"config directory (default: $HOME/.ciphera)",
	)
	root.PersistentFlags().StringVarP(
		&passphrase,
		"passphrase",
		"p",
		"",
		"passphrase to unlock your keys",
	)
	root.PersistentFlags().StringVar(
		&relayURL,
		"relay",
		"",
		"relay URL, e.g. http://127.0.0.1:8080",
	)

	// Register sub-commands.
	root.AddCommand(
		initCmd(),
		fingerprintCmd(),
		registerCmd(),
		startSessionCmd(),
		sendCmd(),
		recvCmd(),
	)

	// Create a signal-aware context so Ctrl-C cancels in-flight HTTP calls.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root.SetContext(ctx)

	return root.Execute()
}
