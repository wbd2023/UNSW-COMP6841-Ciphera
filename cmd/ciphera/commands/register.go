package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// registerCmd generates a signed prekey and a batch of one-time keys, assembles them into a
// PrekeyBundle, and publishes it to the relay.
func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register <username>",
		Short: "Publish your prekey bundle to the relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			user := args[0]

			// Generate and store a signed prekey plus N one-time prekeys.
			_, _, err := appCtx.PrekeyService.GenerateAndStorePrekeys(passphrase, 10)
			if err != nil {
				return fmt.Errorf("generating prekeys: %w", err)
			}

			// Build the public bundle (identity keys, signed prekey, one-time keys).
			bundle, err := appCtx.PrekeyService.LoadPrekeyBundle(passphrase, user)
			if err != nil {
				return fmt.Errorf("loading bundle for %q: %w", user, err)
			}

			// Publish the bundle to the relay.
			if err := appCtx.RelayClient.RegisterPrekeyBundle(cmd.Context(), bundle); err != nil {
				return fmt.Errorf("registering bundle: %w", err)
			}

			fmt.Println("Registered prekeys with relay")
			return nil
		},
	}
	return cmd
}
