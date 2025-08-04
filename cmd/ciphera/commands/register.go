package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register [username]",
		Short: "Publish your prekey bundle to the relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			username = args[0]

			// Generate a signed-prekey and a small batch of OPKs.
			if _, _, err := appCtx.Prekey.GenerateAndStore(passphrase, 10); err != nil {
				return err
			}

			// Assemble the public bundle and cache it.
			bundle, err := appCtx.Prekey.LoadBundle(passphrase, username)
			if err != nil {
				return err
			}

			// Publish to relay.
			if err := appCtx.Relay.Register(bundle); err != nil {
				return err
			}

			fmt.Println("Registered prekeys with relay")
			return nil
		},
	}
	return cmd
}
