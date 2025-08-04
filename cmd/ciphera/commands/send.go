package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// send <peer> <message>: encrypt and send a message to <peer>.
func sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send <peer> <message>",
		Short: "Encrypt and send a message to a peer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if passphrase == "" {
				return fmt.Errorf("passphrase required (-p)")
			}
			if appCtx.Relay == nil {
				return fmt.Errorf("no relay configured. use --relay")
			}
			peer := args[0]
			msg := []byte(args[1])

			if err := appCtx.Messages.Send(passphrase, username, peer, msg); err != nil {
				return err
			}
			fmt.Println("sent")
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "your username (same as you registered with)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}
