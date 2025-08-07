package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

// initCmd creates a new identity (or rotates an existing one) by generating a fresh X25519 and
// Ed25519 keypairs and storing them encrypted on disk.
func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create or rotate your local identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Generate Diffie-Hellman keypair for X3DH
			xpriv, xpub, err := crypto.GenerateX25519()
			if err != nil {
				return fmt.Errorf("generating X25519 key: %w", err)
			}
			// Generate signing keypair
			edpriv, edpub, err := crypto.GenerateEd25519()
			if err != nil {
				return fmt.Errorf("generating Ed25519 key: %w", err)
			}

			// Build and save our identity object
			id := domain.Identity{
				XPub:   xpub,
				XPriv:  xpriv,
				EdPub:  edpub,
				EdPriv: edpriv,
			}
			if err := appCtx.Identity.SaveIdentity(passphrase, id); err != nil {
				return fmt.Errorf("saving identity: %w", err)
			}

			fmt.Println("Identity created.")
			fmt.Printf("Fingerprint: %s\n", crypto.Fingerprint(id.XPub[:]))
			return nil
		},
	}
}
