// Package relay provides an HTTP implementation of the domain.RelayClient
// interface used by ciphera.
//
// The relay acts as a store-and-forward service for encrypted envelopes and
// cryptographic prekey bundles between peers. This package offers a concrete
// HTTP client for interacting with such a relay server.
//
// Supported operations include:
//   - Publishing our prekey bundle to the relay.
//   - Fetching a peer's prekey bundle.
//   - Sending encrypted envelopes to a peer via the relay.
//   - Fetching pending envelopes for a user.
//   - Acknowledging received messages.
//
// All requests are JSON over HTTP and accept a context for cancellation and
// deadlines. Non-2xx statuses are returned as errors with the HTTP method,
// full URL, and status text to aid diagnostics.
package relay
