package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"ciphera/internal/crypto"
	"ciphera/internal/domain"
)

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create or rotate your local identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			xpriv, xpub, err := crypto.GenerateX25519()
			if err != nil {
				return err
			}
			edpriv, edpub, err := crypto.GenerateEd25519()
			if err != nil {
				return err
			}
			id := domain.Identity{XPub: xpub, XPriv: xpriv, EdPub: edpub, EdPriv: edpriv}
			if err := appCtx.Identity.Save(passphrase, id); err != nil {
				return err
			}
			fmt.Println("Identity created.")
			fmt.Printf("Fingerprint: %s\n", crypto.Fingerprint(id.XPub[:]))
			return nil
		},
	}
	return cmd
}
