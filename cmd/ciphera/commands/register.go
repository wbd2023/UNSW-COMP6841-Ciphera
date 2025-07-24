package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register <username>",
		Short: "Generate prekeys and upload a bundle to the relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if passphrase == "" {
				return fmt.Errorf("passphrase required (-p)")
			}
			if appCtx.Relay == nil {
				return fmt.Errorf("no relay configured. use --relay http://host:port")
			}
			username = args[0]

			_, _, err := appCtx.Prekeys.GenerateAndStore(passphrase, 50)
			if err != nil {
				return err
			}
			bundle, err := appCtx.Prekeys.LoadBundle(passphrase, username)
			if err != nil {
				return err
			}
			if err := appCtx.Relay.Register(bundle); err != nil {
				return err
			}
			fmt.Println("Registered prekeys with relay")
			return nil
		},
	}
	return cmd
}
