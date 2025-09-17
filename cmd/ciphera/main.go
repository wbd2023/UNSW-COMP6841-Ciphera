// The entrypoint for the ciphera CLI.
package main

import (
	"log"

	"ciphera/cmd/ciphera/commands"
)

// Initialises and executes the command hierarchy.
func main() {
	if err := commands.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
