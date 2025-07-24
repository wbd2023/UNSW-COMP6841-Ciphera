package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate identity keys and store them securely",
		RunE: func(cmd *cobra.Command, args []string) error {
			if passphrase == "" {
				return fmt.Errorf("passphrase required (-p)")
			}
			_, fp, err := appCtx.IDs.Generate(passphrase)
			if err != nil {
				return err
			}
			fmt.Printf("Identity created.\nFingerprint: %s\n", fp)
			return nil
		},
	}
}
