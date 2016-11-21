package decrypter

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/cryptor"
)

// RODecrypter decrypts RedOctober encrypted secrets
type RODecrypter struct {
	name     string
	password string
	server   *client.RemoteServer
}

// NewRODecrypter returns an decrypter using the provided username/password
// credentials which can decrypt RedOctober secrets that were delegated to that
// user.
func NewRODecrypter(name, password, server, caPath string) (Decrypter, error) {
	s, err := client.NewRemoteServer(server, caPath)
	if err != nil {
		return nil, err
	}
	return &RODecrypter{
		name:     name,
		password: password,
		server:   s,
	}, nil
}

// Decrypt requests the RedOctober server to decrypt the secret and returns
// the decrypted secret and its labels.
func (d *RODecrypter) Decrypt(ct io.Reader) (*Secret, error) {
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
