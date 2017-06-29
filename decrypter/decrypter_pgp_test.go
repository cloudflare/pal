package decrypter

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func TestPGPDecrypter(t *testing.T) {
	decrypter, err := NewPGPDecrypter("aes256", "sha256", "../testdata/secring.gpg", "paltest")
	if err != nil {
		t.Fatalf("failed to initialized pgp decrypter %v", err)
	}
	dec := (decrypter).(*pgpDecrypter)

	buf := bytes.NewBuffer(nil)
	text, err := openpgp.Encrypt(buf, dec.keys, nil, nil, dec.config)
	if err != nil {
		t.Fatalf("failed to encrypt %v", err)
	}
	if _, err := text.Write([]byte(`{"labels":["pal"],"value":"dGhpcyBpcyBhIHRlc3Q="}`)); err != nil {
		t.Fatalf("failed to encrypt data %v", err)
	}
	if err := text.Close(); err != nil {
		t.Fatalf("failed to close writer %v", err)
	}

	sec, err := dec.Decrypt(buf)
	if err != nil {
		t.Fatalf("failed to decrypt secret %v", err)
	}
	if !reflect.DeepEqual(sec.Labels, []string{"pal"}) ||
		!bytes.Equal(sec.Value, []byte("this is a test")) {
		t.Fatalf("wanted labels=%v value=%q, got label=%v value=%q", []string{"pal"},
			"this is a test", sec.Labels, string(sec.Value))
	}
}
