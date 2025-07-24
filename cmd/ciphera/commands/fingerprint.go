package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func fingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Show your identity fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if passphrase == "" {
				return fmt.Errorf("passphrase required (-p)")
			}
			fp, err := appCtx.IDs.Fingerprint(passphrase)
			if err != nil {
				return err
			}
			fmt.Println(fp)
			return nil
		},
	}
}
