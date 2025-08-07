package commands

import (
	"fmt"

	"ciphera/internal/crypto"

	"github.com/spf13/cobra"
)

// fingerprintCmd prints the fingerprint of the stored identity by loading it and hashing its X25519
// public key.
func fingerprintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print identity fingerprint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load full identity (X25519 & Ed25519 keys) from disk
			id, err := appCtx.Identity.LoadIdentity(passphrase)
			if err != nil {
				return err
			}

			// Derive fingerprint from the X25519 public key bytes
			fp := crypto.Fingerprint(id.XPub[:])

			// Display to user
			fmt.Printf("Fingerprint: %s\n", fp)
			return nil
		},
	}
	return cmd
}
