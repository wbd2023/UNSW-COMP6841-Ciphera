package crypto

import "encoding/base64"

// B64 returns standard base64 encoding without newlines.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
