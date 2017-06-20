package pal

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"syscall"

	yaml "gopkg.in/yaml.v2"
)

// Client represents a PAL client capable of issuing deryption requests and
// executing a subprocess with a provided set of environment variables. It
// provides the core functionality for the 'pal' command line tool, and is
// implemented by the ClientV1 and ClientV2 types.
type Client interface {
	// Decrypt sends decryption requests to pald for every secret specified in the
	// configuration for this Client. Upon success, the decrypted plaintexts are
	// stored for use in a future call to Exec.
	Decrypt() error
	// Exec executes the given command with the given environment. It additonally
	// injects any secrets decrypted with a previous call to Decrypt.
	Exec(arg, env []string) error
}

// ConfigEntry represents a parsed PAL client YAML configuration entry. Note
// that this is not the schema for a PAL client YAML configuration file.
// Instead, a PAL client YAML configuration file is itself a map where the keys
// are environment names, and each value is a single entry (represented by this
// type). In other words, the full parsed config file is represented by
// map[string]*ConfigEntry
//
// The following is an example configuration file:
//  dev:
//    entrypoint: env
//    env:
//      TESTVAR: ro:4VUfu2xX0KGcvRmP76e4VkdESQziR1S4kh7/TRoNOVJ
type ConfigEntry struct {
	Envs       map[string]string `yaml:"env,omitempty"`
	Files      map[string]string `yaml:"file,omitempty"`
	EntryPoint string            `yaml:"entrypoint,omitempty"`
	Command    string            `yaml:"command,omitempty"`
}

func loadConfigEntry(r io.Reader, environment string) (*ConfigEntry, error) {
	configs := make(map[string]*ConfigEntry)

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(buf, configs); err != nil {
		return nil, err
	}

	if config, ok := configs[environment]; ok {
		return config, nil
	}

	return nil, fmt.Errorf("missing config section %q", environment)
}

var execFunc = syscall.Exec

func replaceEnvVar(env []string, name, val string) bool {
	prefix := name + "="
	for i := range env {
		if strings.HasPrefix(env[i], prefix) {
			env[i] = prefix + val
			return true
		}
	}
	return false
}

func base64Decode(val string) ([]byte, error) {
	if !strings.HasPrefix(val, "base64:") {
		return []byte(val), nil
	}

	val = strings.TrimPrefix(val, "base64:")
	return base64.StdEncoding.DecodeString(val)
}
