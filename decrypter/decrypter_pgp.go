package decrypter

import (
	"crypto"
	"encoding/json"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type pgpDecrypter struct {
	config *packet.Config
	keys   openpgp.EntityList
}

// NewPGPPacketConfig constructs a new OpenPGP packet configuration from the
// given cipher and hash, as specified in RFC 4880.
func NewPGPPacketConfig(cipher, hash string) *packet.Config {
	return &packet.Config{
		DefaultHash:   pgpHashIDFromName(hash),
		DefaultCipher: pgpCipherIDFromName(cipher),
	}
}

// NewPGPDecrypter returns a new Decrypter that operates by using the provided
// keyring and credentials to perform PGP decryption on ciphertexts.
func NewPGPDecrypter(cipher, hash, keyRingPath, passphrase string) (Decrypter, error) {
	conf := NewPGPPacketConfig(cipher, hash)
	keyringFileBuffer, err := os.Open(keyRingPath)
	if err != nil {
		return nil, err
	}
	defer keyringFileBuffer.Close()
	keys, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		passphraseByte := []byte(passphrase)
		for _, key := range keys {
			if err := key.PrivateKey.Decrypt(passphraseByte); err != nil {
				return nil, err
			}
			for _, subkey := range key.Subkeys {
				if err := subkey.PrivateKey.Decrypt(passphraseByte); err != nil {
					return nil, err
				}
			}
		}
	}
	return &pgpDecrypter{
		config: conf,
		keys:   keys,
	}, nil
}

func (d *pgpDecrypter) Decrypt(r io.Reader) (*Secret, error) {
	md, err := openpgp.ReadMessage(r, d.keys, nil, d.config)
	if err != nil {
		return nil, err
	}
	secret := &Secret{}
	if err := json.NewDecoder(md.UnverifiedBody).Decode(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Convert a named hash algorithm into Go's hash algorithm enumeration for
// parsing configuration
func pgpHashIDFromName(hash string) crypto.Hash {
	lowHash := strings.ToLower(hash)
	// Limit this to secure hashes allowed by RFC 4880
	switch lowHash {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

// Convert a cipher name into an RFC 4880 identifier. Why is there no function
// for this in golang.org/x/crypto/openpgp?
func pgpCipherIDFromName(cipher string) packet.CipherFunction {
	lowCipher := strings.ToLower(cipher)
	switch lowCipher {
	case "3des":
		return packet.Cipher3DES
	case "cast5":
		return packet.CipherCAST5
	case "aes128":
		return packet.CipherAES128
	case "aes192":
		return packet.CipherAES192
	case "aes256":
		return packet.CipherAES256
	default:
		return 0
	}
}
