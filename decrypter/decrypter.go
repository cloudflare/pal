package decrypter

import (
	"io"
	"regexp"
)

var (
	base64Infix = "base64"
	valRegex    *regexp.Regexp
)

func init() {
	valRegex = regexp.MustCompile(`(\w+)\+?(\w*):(.+)`)
}

// A Secret represents a decrypted secret. Each secret can have multiple labels
// and multiple values.
type Secret struct {
	Labels []string `json:"labels"`
	Value  []byte   `json:"value"`
}

// A Decrypter is a generic interface that abstracts away the details of
// performing a decryption. Currently, PGP and Red October are supported.
type Decrypter interface {
	// Decrypt the ciphertext r.
	Decrypt(r io.Reader) (*Secret, error)
}

// SplitPALValue parses a PAL secret, returning the parsed decrypter type,
// whether or not the plaintext is itself base64-encoded, and the value of the
// ciphertext.
func SplitPALValue(line string) (decrypterType string, base64 bool, value string) {
	s := valRegex.FindAllStringSubmatch(line, -1)
	if s == nil || (len(s) != 1 && len(s[0]) != 4) {
		return "", false, ""
	}
	matched := s[0]
	return matched[1], matched[2] == base64Infix, matched[3]
}

// // JoinPALValue encodes a PAL secret plaintext by appending the prefix "base64:"
// // if the base64 argument is true.
// func JoinPALValue(base64 bool, value string) string {
// 	if base64 {
// 		return "base64:" + value
// 	}
// 	return value
// }
