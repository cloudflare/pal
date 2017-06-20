package pal

import (
	"net"
	"os"
	"testing"

	"github.com/joshlf/testutil"
)

func TestServerWithClientV2(t *testing.T) {
	ro := mustROTestInstance(t)
	defer ro.Quit(t)

	listener, tempdir := mustListenUnixSocket(t)
	defer os.RemoveAll(tempdir)
	defer listener.Close()

	const nopSecret = "nom nom nom"

	server, err := NewServer(&ServerConfigEntry{
		ROServer:        ro.serverAddr,
		LabelsRetriever: "mocker",
		CABundle:        ro.cert,
		User:            paldUser,
		Password:        paldPass,
	})
	testutil.MustPrefix(t, "could not create pald server", err)

	go func() {
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	plainCiphertext := ro.mustEncryptAndDelegate(t, plainSecret, []string{testLabel}, []string{testLabel})
	base64Ciphertext := ro.mustEncryptAndDelegate(t, base64Secret, []string{testLabel}, []string{testLabel})

	config := &ConfigEntry{
		Envs: map[string]string{
			"NOP":   nopSecret,
			"PLAIN": "ro:" + plainCiphertext,
			"B64":   "ro+base64:" + base64Ciphertext,
		},
		Files: map[string]string{
			"/path/to/nop":   nopSecret,
			"/path/to/plain": "ro:" + plainCiphertext,
			"/path/to/b64":   "ro+base64:" + base64Ciphertext,
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := newClientV2(config, listener.Addr().String())
	err = client.Decrypt()
	testutil.MustPrefix(t, "could not decrypt secrets", err)

	if got := client.config.Envs["NOP"]; got != nopSecret {
		t.Errorf("want ro: secret %q, got %q", nopSecret, got)
	}
	if got := client.config.Files["/path/to/nop"]; got != nopSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
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

func TestRPCServerWithInvalidLabel(t *testing.T) {
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
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	config := &ConfigEntry{
		Envs: map[string]string{
			"PLAIN": "ro:" + ro.mustEncryptAndDelegate(t, plainSecret, []string{"required-label-but-not-exist"}, nil),
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	err = newClientV2(config, listener.Addr().String()).Decrypt()
	testutil.MustError(t, "code: 101, reason: Failed to decrypt secret: need more delegated keys", err)
}

func TestRPCServerWithoutPeerCred(t *testing.T) {
	ro := mustROTestInstance(t)
	defer ro.Quit(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	testutil.MustPrefix(t, "could not listen", err)
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
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	base64Ciphertext := ro.mustEncryptAndDelegate(t, base64Secret, []string{testLabel}, []string{testLabel})

	config := &ConfigEntry{
		Envs: map[string]string{
			"B64": "ro+base64:" + base64Ciphertext,
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := &clientV2{
		socketAddr: listener.Addr().String(),
		config:     config,
		dialFunc: func(_, _ string) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
	}
	err = client.Decrypt()
	testutil.MustError(t, "code: 101, reason: failed to retrieve peer credential of the connection: internal listener is not a net.UnixListener", err)
}
