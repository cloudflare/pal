package decrypter

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/cryptor"
)

type roDecrypter struct {
	name     string
	password string
	server   *client.RemoteServer
}

// NewRODecrypter returns a new Decrypter that operates by making decryption
// requests to the specified Red October server with the given credentials.
//
// caPath is a path to a CA file that will be used to validate the server's
// identity. If it is empty, the system's default CA pool will be used.
func NewRODecrypter(name, password, server, caPath string) (Decrypter, error) {
	s, err := client.NewRemoteServer(server, caPath)
	if err != nil {
		return nil, err
	}
	return &roDecrypter{
		name:     name,
		password: password,
		server:   s,
	}, nil
}

func (d *roDecrypter) Decrypt(ct io.Reader) (*Secret, error) {
	data, err := ioutil.ReadAll(ct)
	if err != nil {
		return nil, err
	}
	labels, err := parseROLabels(data)
	if err != nil {
		return nil, err
	}
	req := core.DecryptRequest{
		Name:     d.name,
		Password: d.password,
		Data:     data,
	}
	resp, err := d.server.Decrypt(req)
	if err != nil {
		return nil, err
	}
	decryptedData := new(core.DecryptWithDelegates)
	if err := json.Unmarshal(resp.Response, decryptedData); err != nil {
		return nil, err
	}
	return &Secret{
		Labels: labels,
		Value:  decryptedData.Data,
	}, nil
}

func parseROLabels(data []byte) ([]string, error) {
	sealedData := new(cryptor.EncryptedData)
	if err := json.Unmarshal([]byte(data), sealedData); err != nil {
		return nil, err
	}
	encryptedData := new(cryptor.EncryptedData)
	if err := json.Unmarshal(sealedData.Data, encryptedData); err != nil {
		return nil, err
	}
	return encryptedData.Labels, nil
}
