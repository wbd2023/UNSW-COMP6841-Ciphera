package commands

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"ciphera/internal/app"
	"ciphera/internal/domain"
	"ciphera/internal/relay"
	identitysvc "ciphera/internal/services/identity"
	prekeysvc "ciphera/internal/services/prekey"
	sessionsvc "ciphera/internal/services/session"
	"ciphera/internal/store"
)

var (
	home       string
	passphrase string
	appCtx     *app.App

	relayURL string
	username string
)

func Execute() error {
	root := &cobra.Command{
		Use:   "ciphera",
		Short: "End-to-end encrypted chat CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if home == "" {
				dir, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				home = filepath.Join(dir, ".ciphera")
			}
			if err := os.MkdirAll(home, 0o700); err != nil {
				return err
			}

			fs := store.NewFileStore(home)
			idsvc := identitysvc.New(fs)
			pksvc := prekeysvc.New(idsvc, fs, fs)

			var rc domain.RelayClient
			if relayURL != "" {
				hc := &http.Client{Transport: http.DefaultTransport}
				httpRelay := relay.NewHTTP(relayURL)
				httpRelay.HTTP = hc
				rc = httpRelay
			}

			sessStore := store.NewSessionStore(home)
			sessSvc := sessionsvc.New(idsvc, fs, rc, sessStore)

			appCtx = app.New(idsvc, pksvc, rc, sessSvc)
			return nil
		},
	}

	root.PersistentFlags().StringVar(&home, "home", "", "config dir (default ~/.ciphera)")
	root.PersistentFlags().StringVarP(&passphrase, "passphrase", "p", "", "passphrase to protect keys")
	root.PersistentFlags().StringVar(&relayURL, "relay", "", "relay base URL (e.g. http://127.0.0.1:8080)")

	root.AddCommand(
		initCmd(),
		fingerprintCmd(),
		registerCmd(),
		startSessionCmd(),
	)
	return root.Execute()
}
