package main

import (
	"os"

	"ciphera/cmd/ciphera/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
