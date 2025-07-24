package commands

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"ciphera/internal/app"
	"ciphera/internal/services/identity"
	"ciphera/internal/store"
)

var (
	home       string
	passphrase string
	appCtx     *app.App
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
			idsvc := identity.New(fs)
			appCtx = app.New(idsvc)
			return nil
		},
	}

	root.PersistentFlags().StringVar(&home, "home", "", "config dir (default ~/.ciphera)")
	root.PersistentFlags().StringVarP(&passphrase, "passphrase", "p", "", "passphrase to protect keys")

	root.AddCommand(initCmd(), fingerprintCmd())
	return root.Execute()
}
