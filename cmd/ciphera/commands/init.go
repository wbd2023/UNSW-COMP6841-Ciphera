package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// initCmd creates a new identity (or rotates an existing one) by generating a fresh
// X25519 and Ed25519 keypair and storing them encrypted on disk.
func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create or rotate your local identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create and persist a new identity via the identity service.
			_, fp, err := appCtx.IdentityService.GenerateIdentity(passphrase)
			if err != nil {
				return fmt.Errorf("creating identity: %w", err)
			}

			fmt.Println("Identity created")
			fmt.Printf("Fingerprint: %s\n", fp)
			return nil
		},
	}
}
