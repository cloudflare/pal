package pal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	shellwords "github.com/mattn/go-shellwords"
)

type config struct {
	Envs       map[string]string `yaml:"env,omitempty"`
	Files      map[string]string `yaml:"file,omitempty"`
	EntryPoint string            `yaml:"entrypoint,omitempty"`
	Command    string            `yaml:"command,omitempty"`
}

func loadConfig(r io.Reader, environment string) (*config, error) {
	configs := make(map[string]*config)

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

// Client is a PAL client. iIt can communicates with the PAL daemon, sends the
// secret decryption requests, receive the decrypted secrets, setup and execute
// the chosen program in an correct environment.
type Client struct {
	socketAddr string
	dialFunc   func(network, addr string) (net.Conn, error)
	config     *config
}

// NewClient initializes a Client given its configuration stream, PAL socket
// address and its environment.
func NewClient(r io.Reader, socketAddr, appEnv string) (*Client, error) {
	config, err := loadConfig(r, appEnv)
	if err != nil {
		return nil, err
	}

	return newClient(config, socketAddr), nil
}

func newClient(config *config, socketAddr string) *Client {
	dialFunc := func(_, _ string) (net.Conn, error) {
		return net.Dial("unix", socketAddr)
	}

	return &Client{
		socketAddr: socketAddr,
		dialFunc:   dialFunc,
		config:     config,
	}
}

// Decrypt requests PAL server to decrypt the encrypted secrets
func (c *Client) Decrypt() error {
	if err := c.decryptMap(c.config.Envs); err != nil {
		return fmt.Errorf("Failed to decrypt env secrets: %v", err)
	}
	if err := c.decryptMap(c.config.Files); err != nil {
		return fmt.Errorf("Failed to decrypt file secrets: %v", err)
	}
	return nil
}

// Exec setups correct secret environment variables and secret files then
// executes the given command. It must only be called after the client finished
// decrypting its secrets by calling Decrypt()
func (c *Client) Exec(argv, environ []string) error {
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

func (c *Client) decryptMap(m map[string]string) error {
	dreq := &decryptionRequest{
		Ciphertexts: make(map[string]string),
	}
	for k, v := range m {
		if isSecret(v) {
			dreq.Ciphertexts[k] = v
		}
	}
	dresp, err := c.doRPCDecryptionRequest(dreq)
	if err != nil {
		return err
	}
	for k, v := range dresp.Secrets {
		m[k] = v
	}
	return nil
}

func (c *Client) doRPCDecryptionRequest(dreq *decryptionRequest) (*decryptionResponse, error) {
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
