package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// recvCmd fetches any queued ciphertexts, decrypts them and prints them.
func recvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recv",
		Short: "Fetch and decrypt your queued messages",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// 0 = no limit, fetch everything
			msgs, err := appCtx.Messages.Receive(passphrase, username, 0)
			if err != nil {
				return fmt.Errorf("receiving messages: %w", err)
			}

			for _, m := range msgs {
				fmt.Printf("[%s] %s\n", m.From, string(m.Plaintext))
			}
			return nil
		},
	}

	// Username flag is local to this command
	cmd.Flags().StringVarP(&username, "username", "u", "", "your registered username")
	_ = cmd.MarkFlagRequired("username")

	return cmd
}
