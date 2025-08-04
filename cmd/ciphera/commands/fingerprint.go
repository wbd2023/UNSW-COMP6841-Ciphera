package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"ciphera/internal/crypto"
)

func fingerprintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print identity fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := appCtx.Identity.LoadIdentity(passphrase)
			if err != nil {
				return err
			}
			fp := crypto.Fingerprint(id.XPub[:])
			fmt.Printf("Fingerprint: %s\n", fp)
			return nil
		},
	}
	return cmd
}
