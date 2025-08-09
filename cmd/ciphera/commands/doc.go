// Package commands defines the ciphera CLI and wires dependencies for subcommands.
//
// Commands
//
//   - init           Create or rotate the local identity
//   - fingerprint    Print the identity fingerprint
//   - register       Publish your prekey bundle to a relay
//   - start-session  Establish an X3DH session with a peer
//   - send           Encrypt and send a message
//   - recv           Fetch and decrypt queued messages
//
// # Implementation
//
// The root command constructs an HTTP client and builds a dependency graph
// (stores, services, relay client) before any subcommand runs, so handlers can
// use a shared app context with timeouts and connection pooling.
package commands
