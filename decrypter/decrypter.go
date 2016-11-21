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

// Secret contains the decrypted secrets and its associated labels
type Secret struct {
	Labels []string `json:"labels"`
	Value  []byte   `json:"value"`
}

// A Decrypter provides implentation to decrypt its compatible encrypted secrets
type Decrypter interface {
	// Decrypt  returns the decrypted secret and its labels as `Secret`
	Decrypt(io.Reader) (*Secret, error)
}

// SplitPALValue split the PAL-scheme message contains the encrypted secret,
// the decrypter type and whether the encrypted secret is binary hence should be
// base64-encoded before sending back to the client.
//
// The format can be noted as:
//		decrypterType[+base64]:encryptedSecret
func SplitPALValue(line string) (decrypterType string, binary bool, value string) {
	s := valRegex.FindAllStringSubmatch(line, -1)
	if len(s) != 1 && len(s[0]) != 4 {
		return "", false, ""
	}
	matched := s[0]
	return matched[1], matched[2] == base64Infix, matched[3]
}

// JoinPalValue returns the value that should be sent to the client taking into
// account whether the value is base64-encoded, hence should be decoded by the
// client.
func JoinPalValue(binary bool, value string) string {
	if binary {
		return "base64:" + value
	}
	return value
}
