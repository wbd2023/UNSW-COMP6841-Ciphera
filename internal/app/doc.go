// Package app wires application dependencies for the CLI.
//
// It builds the concrete stores, protocol clients and high-level services
// from Config, exposing them via the Wire struct for commands to use.
package app
