package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"ciphera/internal/domain"
)

// registerCmd generates a Signed Pre-Key and a batch of One-Time Pre-Keys, assembles them into a
// PreKeyBundle, and publishes it to the relay.
func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register <username>",
		Short: "Publish your prekey bundle to the relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			usernameValue := domain.Username(args[0])

			// Generate and store a Signed Pre-Key plus N One-Time Pre-Keys.
			_, _, err := appCtx.PreKeyService.GenerateAndStorePreKeys(passphrase, 10)
			if err != nil {
				return fmt.Errorf("generating prekeys: %w", err)
			}

			// Build the public bundle (identity keys, Signed Pre-Key, One-Time Pre-Keys).
			bundle, err := appCtx.PreKeyService.LoadPreKeyBundle(passphrase, usernameValue)
			if err != nil {
				return fmt.Errorf("loading bundle for %q: %w", usernameValue, err)
			}

			// Publish the bundle to the relay.
			if err := appCtx.RelayClient.RegisterPreKeyBundle(cmd.Context(), bundle); err != nil {
				return fmt.Errorf("registering bundle: %w", err)
			}

			fmt.Println("Registered pre-keys with relay")
			return nil
		},
	}
	return cmd
}
