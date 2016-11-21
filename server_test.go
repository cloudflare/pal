package pal

import "testing"

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
