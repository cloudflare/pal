package pal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		config *config
		Env    string
		Err    error
	}{
		// valid configs
		{
			Env: "production",
			config: &config{
				Envs: map[string]string{
					"FOO_BAR": "ro:CIPHERTEXT",
				},
				Files: map[string]string{
					"/foo/bar/baz": "ro+base64:AAAAAAA",
				},
				EntryPoint: "/usr/bin/reefer \\\n  -t /templates/nginx.conf.tmpl:/etc/nginx/nginx.conf \\\n  -E\n",
				Command:    "exec /bar -addr :${PORT}",
			},
		},
		{
			Env: "staging",
			config: &config{
				Envs: map[string]string{
					"BAZ": "PLAIN TEXT VALUE",
				},
				Files: map[string]string{
					"/foo/bar/baz": "base64:ABCD==",
				},
				EntryPoint: "/usr/bin/reefer \\\n  -t /templates/nginx.conf.tmpl:/etc/nginx/nginx.conf \\\n  -E\n",
				Command:    "exec /bar -addr :${PORT}",
			},
		},
		// missing config for environment
		{
			Env: "non-existent",
			Err: errors.New(`missing config section "non-existent"`),
		},
	}

	for _, test := range tests {
		buf := bytes.NewBufferString(testYAML)

		config, err := loadConfig(buf, test.Env)
		if err != nil {
			if test.Err != nil {
				if test.Err.Error() != err.Error() {
					t.Errorf("want err %q, got %q", test.Err, err)
				}
				continue
			}
			t.Error(err)
			continue
		}

		if !reflect.DeepEqual(test.config, config) {
			t.Errorf("want config %+v, got %+v", test.config, config)
		}
	}
}

var testYAML = `
default: &DEFAULT
  entrypoint: |
    /usr/bin/reefer \
      -t /templates/nginx.conf.tmpl:/etc/nginx/nginx.conf \
      -E
  command: exec /bar -addr :${PORT}

production:
  <<: *DEFAULT
  env:
    FOO_BAR: ro:CIPHERTEXT
  file:
    /foo/bar/baz: ro+base64:AAAAAAA

staging:
  <<: *DEFAULT
  env:
    BAZ: PLAIN TEXT VALUE
  file:
    /foo/bar/baz: base64:ABCD==`

func TestClientExec(t *testing.T) {
	var (
		gotArgv0 string
		gotArgv  []string
		gotEnvv  []string
	)

	execFunc = func(argv0 string, argv []string, envv []string) error {
		gotArgv0, gotArgv, gotEnvv = argv0, argv, envv
		return nil
	}

	tmpdir, err := ioutil.TempDir("", "pal-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	cfg := &config{
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := newClient(cfg, path.Join(tmpdir, "test.sock"))

	// assume that the secrets have been decrypted here
	client.envSecrets = map[string]string{
		"FOO": "uno",
		"BAR": base64Encode("dos"),
		"BAZ": "tres",
	}
	client.fileSecrets = map[string]string{
		path.Join(tmpdir, "plain"):  "plain text data",
		path.Join(tmpdir, "base64"): base64Encode("base64 encoded data"),
	}

	argv := []string{
		"/path/to/cmd",
		"-argv-flag",
		"flag-val",
	}
	envv := []string{
		"BAZ=not tres", // to be replaced by 'tres'
		"BANG=cuatro",
	}

	if err := client.Exec(argv, envv); err != nil {
		t.Fatal(err)
	}

	// test argv0 is first entrypoint arg
	if gotArgv0 != "/usr/bin/env" {
		t.Errorf("want argv0 = '/usr/bin/env', got %q", gotArgv0)
	}

	wantArgv := []string{
		"env",
		"-t",
		"/foo/bar.tmpl:/foo/bar",
		"-E",
		"/bin/sh",
		"-c",
		"true -entrypoint-flag=foo -- /path/to/cmd -argv-flag flag-val",
	}

	// test argv is <entrypoint-tokens...> + /bin/sh -c '<command> <argv...>'
	if !reflect.DeepEqual(wantArgv, gotArgv) {
		t.Errorf("want argv %+v, got %+v", wantArgv, gotArgv)
	}

	wantEnvv := []string{
		"FOO=uno",
		"BAR=dos",  // plain text
		"BAZ=tres", // replaced
		"BANG=cuatro",
	}

	sort.Strings(wantEnvv)
	sort.Strings(gotEnvv)

	// test envv is collapsed & decoded
	if !reflect.DeepEqual(wantEnvv, gotEnvv) {
		t.Errorf("want envv %+v, got %+v", wantEnvv, gotEnvv)
	}

	// test plain text file is created
	got, err := ioutil.ReadFile(path.Join(tmpdir, "plain"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "plain text data" {
		t.Errorf("want file data = 'plain text data', got %q", string(got))
	}

	data, err := ioutil.ReadFile(path.Join(tmpdir, "base64"))
	if err != nil {
		t.Fatal(err)
	}

	got, err = base64Decode(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "base64 encoded data" {
		t.Errorf("want file data = 'base64 encoded data', got %q", string(got))
	}
}

func base64Encode(val string) string {
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(val))
}
