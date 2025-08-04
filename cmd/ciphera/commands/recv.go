package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// recv: fetch and decrypt queued messages for --username.
func recvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recv",
		Short: "Fetch and decrypt your queued messages",
		RunE: func(cmd *cobra.Command, args []string) error {
			if passphrase == "" {
				return fmt.Errorf("passphrase required (-p)")
			}
			if appCtx.Relay == nil {
				return fmt.Errorf("no relay configured. use --relay")
			}
			if username == "" {
				return fmt.Errorf("--username required")
			}

			msgs, err := appCtx.Messages.Recv(passphrase, username, 0)
			if err != nil {
				return err
			}
			for _, m := range msgs {
				fmt.Printf("[%s] %s\n", m.From, string(m.Plaintext))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "your username (same as you registered with)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}
