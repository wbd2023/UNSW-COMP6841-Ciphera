package commands

import (
    "fmt"

    "github.com/spf13/cobra"
)

// start-session <peer>: perform X3DH with the peer's bundle and store a session.
func startSessionCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "start-session <peer>",
        Short: "Run X3DH against the peer's prekey bundle and create a session",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            if passphrase == "" {
                return fmt.Errorf("passphrase required (-p)")
            }
            if appCtx.Relay == nil {
                return fmt.Errorf("no relay configured. use --relay")
            }
            peer := args[0]
            sess, err := appCtx.Sessions.StartInitiator(passphrase, peer)
            if err != nil {
                return err
            }
            fmt.Printf("Session created with %s. RootKey=%x\n", peer, sess.RootKey)
            return nil
        },
    }
    return cmd
}
