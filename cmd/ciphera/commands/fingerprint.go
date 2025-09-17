package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// fingerprintCmd prints the fingerprint of the stored identity.
func fingerprintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print identity fingerprint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fp, err := appCtx.IdentityService.FingerprintIdentity(passphrase)
			if err != nil {
				return fmt.Errorf("loading fingerprint: %w", err)
			}
			fmt.Printf("Fingerprint: %s\n", fp)
			return nil
		},
	}
	return cmd
}
