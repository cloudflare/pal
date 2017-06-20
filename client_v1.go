package pal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudflare/pal/log"
	"github.com/mattn/go-shellwords"
)

type clientV1 struct {
	httpClient *http.Client
	config     *ConfigEntry
}

// NewClientV1 constructs a new Client that implements version 1 of the PAL
// protocol. r is a PAL YAML configuration, socketAddr is the file path to the
// pald socket, and appEnv is the environment from the config to use.
//
// If there is an error reading or parsing r, NewClientV1 will abort the
// process.
func NewClientV1(r io.Reader, socketAddr, appEnv string) Client {
	config, err := loadConfigEntry(r, appEnv)
	if err != nil {
		log.Fatal(err)
	}
	return newClientV1(config, socketAddr)
}

func newClientV1(config *ConfigEntry, socketAddr string) *clientV1 {
	return &clientV1{
		config: config,
		httpClient: &http.Client{
			Transport: &http.Transport{
				Dial: func(_, _ string) (net.Conn, error) {
					return net.Dial("unix", socketAddr)
				},
			},
		},
	}
}

func (c *clientV1) Decrypt() error {
	if c.hasSecrets(c.config.Envs) {
		if err := c.decryptMap(c.config.Envs); err != nil {
			log.Errorf("Failed to decrypt env secrets: %v", err)
			return err
		}
	}
	if c.hasSecrets(c.config.Files) {
		if err := c.decryptMap(c.config.Files); err != nil {
			log.Errorf("Failed to decrypt file secrets: %v", err)
			return err
		}
	}
	return nil
}

func (c *clientV1) Exec(argv, environ []string) error {
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

func (c *clientV1) decryptMap(m map[string]string) error {
	dreq := new(decryptionRequest)
	dreq.Ciphertexts = make(map[string]string)
	for k, v := range m {
		if strings.HasPrefix(v, "ro:") {
			dreq.Ciphertexts[k] = strings.TrimPrefix(v, "ro:")
		} else if strings.HasPrefix(v, "ro+base64:") {
			dreq.Ciphertexts[k] = strings.TrimPrefix(v, "ro+base64:")
		}
	}
	dresp, err := c.doDecryptionRequest(dreq)
	if err != nil {
		return err
	}
	for k, v := range dresp.Secrets {
		if strings.HasPrefix(m[k], "ro+base64:") {
			v = "base64:" + v
		}
		m[k] = v
	}
	return nil
}

func (c *clientV1) doDecryptionRequest(dreq *decryptionRequest) (*decryptionResponse, error) {
	dreqJSON, err := json.Marshal(dreq)
	if err != nil {
		log.Errorf("Failed  to encode env secrets request: %v", err)
		return nil, err
	}
	dreqBodyBuffer := bytes.NewBuffer(dreqJSON)
	req, err := http.NewRequest("POST", "http://localhost", dreqBodyBuffer)
	if err != nil {
		log.Errorf("Couldn't create new HTTP request: %v", err)
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Errorf("Failed to decrypt secrets request: %v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf(err.Error())
		}

		return nil, fmt.Errorf("Secrets decryption request returned %q: %s", resp.Status, body)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	dresp := new(decryptionResponse)

	if err = json.Unmarshal(body, dresp); err != nil {
		log.Errorf("Failed to unmarshal Red October response: %v", err)
		return nil, err
	}
	return dresp, nil
}

func (c *clientV1) hasSecrets(section map[string]string) bool {
	secretPrefixes := []string{
		"ro:",
		"ro+base64:",
	}
	for _, v := range section {
		for _, prefix := range secretPrefixes {
			if strings.HasPrefix(v, prefix) {
				return true
			}
		}
	}
	return false
}
