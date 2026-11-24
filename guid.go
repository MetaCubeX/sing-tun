package tun

import (
	"encoding/hex"
	"errors"
)

// ParseGUID parses a canonical textual GUID, as in
// "00000000-0000-0000-0000-000000000000", into the 16 bytes it denotes.
// The form is all that is accepted, not the other ones a UUID may take, such
// as one without hyphens.
func ParseGUID(s string) ([16]byte, error) {
	var guid [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return guid, errors.New("invalid guid: " + s + ", want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	compact := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(guid[:], []byte(compact)); err != nil {
		return guid, errors.New("invalid guid: " + s)
	}
	return guid, nil
}
