package types

// Envelope is the wire-format message you post/get from the relay.
type Envelope struct {
	From           Username       `json:"from"`
	To             Username       `json:"to"`
	Header         RatchetHeader  `json:"header"`
	Cipher         []byte         `json:"cipher"`
	AssociatedData []byte         `json:"associated_data,omitempty"`
	PreKey         *PreKeyMessage `json:"pre_key,omitempty"`
	Timestamp      int64          `json:"timestamp"`
}

// DecryptedMessage is what MessageService.ReceiveMessage returns.
type DecryptedMessage struct {
	From      Username `json:"from"`
	To        Username `json:"to"`
	Plaintext []byte   `json:"plaintext"`
	Timestamp int64    `json:"timestamp"`
}
