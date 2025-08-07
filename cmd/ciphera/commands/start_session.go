package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// startSessionCmd performs the X3DH handshake against a peer’s prekey bundle and persists a new
// session for future messaging.
func startSessionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start-session <peer>",
		Short: "Establish a secure session with a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := args[0]

			// Initiate handshake and store session state
			sess, err := appCtx.Sessions.Initiate(passphrase, peer)
			if err != nil {
				return fmt.Errorf("starting session with %q: %w", peer, err)
			}

			// Print the root key so users know it succeeded
			fmt.Printf("Session created with %s. RootKey=%x\n", peer, sess.RootKey)
			return nil
		},
	}
}
