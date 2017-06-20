package pal

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudflare/pal/log"
	"github.com/mattn/go-shellwords"
)

type clientV2 struct {
	socketAddr string
	dialFunc   func(network, addr string) (net.Conn, error)
	config     *ConfigEntry
}

// NewClientV2 constructs a new Client that implements version 2 of the PAL
// protocol. r is a PAL YAML configuration, socketAddr is the file path to the
// pald socket, and appEnv is the environment from the config to use.
//
// If there is an error reading or parsing r, NewClientV2 will abort the
// process.
func NewClientV2(r io.Reader, socketAddr, appEnv string) Client {
	config, err := loadConfigEntry(r, appEnv)
	if err != nil {
		log.Fatal(err)
	}
	return newClientV2(config, socketAddr)
}

func newClientV2(config *ConfigEntry, socketAddr string) *clientV2 {
	return &clientV2{
		socketAddr: socketAddr,
		dialFunc: func(_, _ string) (net.Conn, error) {
			return net.Dial("unix", socketAddr)
		},
		config: config,
	}
}

// Decrypt sends decryption requests to pald for every secret specified in the
// configuration for this Client. Upon success, the decrypted plaintexts are
// stored for use in a future call to Exec.
func (c *clientV2) Decrypt() (err error) {
	if err := c.decryptMap(c.config.Envs); err != nil {
		log.Errorf("Failed to decrypt env secrets: %v", err)
		return err
	}
	if err := c.decryptMap(c.config.Files); err != nil {
		log.Errorf("Failed to decrypt file secrets: %v", err)
		return err
	}
	return nil
}

// Exec executes the given command with the given environment. It additonally
// injects any secrets decrypted with a previous call to Decrypt.
func (c *clientV2) Exec(argv, environ []string) error {
	if c.config.Command != "" {
		cmd := append([]string{c.config.Command}, argv...)

		argv = []string{
			"/bin/sh",
			"-c",
			strings.Join(cmd, " "),
		}
	}

	if c.config.EntryPoint != "" {
		epArgv, err := shellwords.Parse(c.config.EntryPoint)
		if err != nil {
			return err
		}

		argv = append(epArgv, argv...)
	}

	argv0, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	env := make([]string, len(environ), len(environ)+len(c.config.Envs))
	copy(env, environ)

	for k, v := range c.config.Envs {
		data, err := base64Decode(v)
		if err != nil {
			return err
		}

		if replaced := replaceEnvVar(env, k, string(data)); !replaced {
			env = append(env, k+"="+string(data))
		}
	}

	for path, val := range c.config.Files {
		data, err := base64Decode(val)
		if err != nil {
			return err
		}

		f, err := os.Create(path)
		if err != nil {
			return err
		}

		_, err = f.Write(data)
		if err != nil {
			return err
		}

		if err := f.Close(); err != nil {
			return err
		}
	}

	return execFunc(argv0, argv, env)
}

func (c *clientV2) decryptMap(m map[string]string) error {
	dreq := &decryptionRequest{
		Ciphertexts: make(map[string]string),
	}
	for k, v := range m {
		if isSecret(v) {
			dreq.Ciphertexts[k] = v
		}
	}

	dresp, err := c.doRPCdecryptionRequest(dreq)
	if err != nil {
		return err
	}

	for k, v := range dresp.Secrets {
		m[k] = v
	}

	return nil
}

func (c *clientV2) doRPCdecryptionRequest(dreq *decryptionRequest) (*decryptionResponse, error) {
	conn, err := c.dialFunc("unix", c.socketAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var (
		decoder = json.NewDecoder(conn)
		encoder = json.NewEncoder(conn)
		dresp   = new(decryptionResponse)
	)
	if err := encoder.Encode(dreq); err != nil {
		return nil, err
	}
	if err := decoder.Decode(dresp); err != nil {
		log.Errorf("Failed to unmarshal PAL response: %v", err)
		return nil, err
	}
	if dresp.Error != nil {
		return dresp, dresp.Error
	}
	return dresp, nil
}

func isSecret(v string) bool {
	secretPrefixes := []string{
		"ro:",
		"ro+base64:",
		"pgp:",
		"pgp+base64:",
	}
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}
