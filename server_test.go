package pal

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/redoctober/cryptor"
)

func TestParseROLabel(t *testing.T) {
	tests := []struct {
		ciphertext []byte
		label      string
	}{
		{
			ciphertext: stagingJSON,
			label:      "staging",
		},
	}

	for _, test := range tests {
		got, err := parseROLabel(test.ciphertext)
		if err != nil {
			t.Error(err)
			continue
		}

		if test.label != got {
			t.Errorf("want label %q, got %q", test.label, got)
		}
	}
}

func parseROLabel(data []byte) (string, error) {
	ed := new(cryptor.EncryptedData)
	if err := json.Unmarshal([]byte(data), ed); err != nil {
		return "", err
	}
	if len(ed.Labels) > 0 {
		return ed.Labels[0], nil
	}
	return "", nil
}

var (
	stagingJSON = []byte(`{
		"Version": 1,
		"VaultId": 12345,
		"Labels": [
		"staging"
		],
		"KeySet": [
		{
			"Name": [
			"benburkert",
			"jkroll"
			],
			"Key": "ffffffffffffffffffffff=="
		}
		],
		"KeySetRSA": {
			"benburkert": {
				"Key": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			},
			"jkroll": {
				"Key": "dddddddddddddddddddddddddddddddddddddddd"
			}
		},
		"IV": "cccccccccccccccccccccc==",
		"Data": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
		"Signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaa="
	}`)
)
