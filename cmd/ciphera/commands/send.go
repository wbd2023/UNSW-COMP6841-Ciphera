package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"ciphera/internal/domain"
)

// sendCmd encrypts and sends a message to <peer>, after validating inputs.
func sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send <peer> <message>",
		Short: "Encrypt and send a message to a peer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			peerUsername := domain.Username(args[0])
			messageBytes := []byte(args[1])

			// Handles unlocking keys, ratchet state, and HTTP post via appCtx.
			err := appCtx.MessageService.SendMessage(
				cmd.Context(),
				passphrase,
				domain.Username(username),
				peerUsername,
				messageBytes,
			)
			if err != nil {
				return fmt.Errorf("sending message to %q: %w", peerUsername, err)
			}

			fmt.Println("Message sent")
			return nil
		},
	}

	// Username flag is local to this command (others inherit from the root).
	cmd.Flags().StringVarP(
		&username,
		"username",
		"u",
		"",
		"your registered username",
	)
	_ = cmd.MarkFlagRequired("username")

	return cmd
}
