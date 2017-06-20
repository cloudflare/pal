package pal

import (
	"net/http"
	"os"
	"testing"

	"github.com/joshlf/testutil"
)

func TestServerWithClientV1(t *testing.T) {
	ro := mustROTestInstance(t)
	defer ro.Quit(t)

	listener, tempdir := mustListenUnixSocket(t)
	defer os.RemoveAll(tempdir)
	defer listener.Close()

	server, err := NewServer(&ServerConfigEntry{
		ROServer:        ro.serverAddr,
		LabelsRetriever: "mocker",
		CABundle:        ro.cert,
		User:            paldUser,
		Password:        paldPass,
	})
	testutil.MustPrefix(t, "could not create pald server", err)

	go func() {
		err := http.Serve(listener, server)
		if err != nil {
			t.Log(err)
		}
	}()

	plainCiphertext := ro.mustEncryptAndDelegate(t, plainSecret, []string{testLabel}, []string{testLabel})
	base64Ciphertext := ro.mustEncryptAndDelegate(t, base64Secret, []string{testLabel}, []string{testLabel})

	config := &ConfigEntry{
		Envs: map[string]string{
			"PLAIN": "ro:" + plainCiphertext,
			"B64":   "ro+base64:" + base64Ciphertext,
		},
		Files: map[string]string{
			"/path/to/plain": "ro:" + plainCiphertext,
			"/path/to/b64":   "ro+base64:" + base64Ciphertext,
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := newClientV1(config, listener.Addr().String())
	err = client.Decrypt()
	testutil.MustPrefix(t, "could not decrypt", err)

	if got := client.config.Envs["PLAIN"]; got != plainSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
	if got := client.config.Files["/path/to/plain"]; got != plainSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
	if got := client.config.Envs["B64"]; got != "base64:"+base64Secret {
		t.Errorf("want ro+base64: secret %q, got %q", "base64:"+base64Secret, got)
	}
	if got := client.config.Files["/path/to/b64"]; got != "base64:"+base64Secret {
		t.Errorf("want ro+base64: secret %q, got %q", "base64:"+base64Secret, got)
	}
}
