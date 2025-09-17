// Package main runs the in-memory HTTP relay used by Ciphera during development
// and tests. It stores published prekey bundles and queues encrypted envelopes
// for recipients until they fetch them.
//
// HTTP API
//
//	POST /register
//	    Store a user's PrekeyBundle (identity key, signed prekey + sig, OPKs).
//
//	GET /prekey/{username}
//	    Return the latest published PrekeyBundle for {username}.
//
//	POST /msg/{user}
//	    Enqueue an Envelope destined to {user}. If Timestamp is zero, the
//	    server fills it with the current Unix time.
//
//	GET /msg/{user}?limit=N
//	    Return up to N queued Envelopes for {user}. If limit is absent or
//	    greater than the queue length, all queued envelopes are returned.
//
//	POST /msg/{user}/ack { "count": N }
//	    Drop the first N queued envelopes for {user}. If N exceeds the queue
//	    length, the queue is cleared.
//
// Behaviour
//
//   - All state is held in memory and lost on process exit.
//   - Responses are JSON. Non-2xx statuses carry a short error message.
//   - A lightweight access log records method, path, remote, status, bytes and
//     duration for each request.
//   - The default listen address is :8080.
//
// AS of now, this relay is intended for local use or as an untrusted middleman
// on a private network. It never sees plaintext or private keys; it only stores
// ciphertext and public bundles.
package main
