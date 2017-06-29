package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cloudflare/pal/decrypter"
	"github.com/cloudflare/pal/log"

	"golang.org/x/crypto/openpgp"
)

var (
	Version = "This is filled at build time"

	labels      = flag.String("labels", "", "required: comma-separated string of labels")
	cipher      = flag.String("cipher", "aes256", "pgp cipher")
	hash        = flag.String("hash", "sha256", "pgp hash")
	keyIDs      = flag.String("keyids", "", `required: comma-separated full key ids (e.g. "6C7EE1B8621CC013") that can decrypt the message`)
	pubRingPath = flag.String("pubring", os.Getenv("HOME")+"/.gnupg/pubring.gpg", "pgp pubring location")
	version     = flag.Bool("v", false, "show the version number and exit")
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		os.Exit(0)
	}

	labelList := strings.Split(*labels, ",")
	if len(labelList) == 0 || len(labelList[0]) == 0 {
		fmt.Println("Label list is required")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println("Example:")
		fmt.Println("  echo -n my-secret-pgp-password | palpgpenc -labels=testpal -keyids=6C7EE1B8621CC013")
		os.Exit(1)
	}

	keyIDList := strings.Split(*keyIDs, ",")
	if len(keyIDList) == 0 || len(keyIDList[0]) == 0 {
		fmt.Println("Key IDs are required")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println("Example:")
		fmt.Println("  echo -n my-secret-pgp-password | palpgpenc -labels=testpal -keyids=6C7EE1B8621CC013")
		os.Exit(1)
	}

	conf := decrypter.NewPGPPacketConfig(*cipher, *hash)
	pubRing, err := os.Open(*pubRingPath)
	if err != nil {
		log.Fatalf("Failed to open pubring %v", err)
	}
	pubKeys, err := openpgp.ReadKeyRing(pubRing)
	if err != nil {
		log.Fatalf("Failed to open pubring %v", err)
	}
	if err := pubRing.Close(); err != nil {
		log.Fatalf("Failed to close pubring %v", err)
	}

	recipients := []*openpgp.Entity{}
	for _, k := range pubKeys {
		for _, keyID := range keyIDList {
			// first check the primary key for matched key id
			if k.PrimaryKey.KeyIdString() == keyID {
				recipients = append(recipients, k)
			} else {
				// check the sub key for matched key id
				for _, subkey := range k.Subkeys {
					if subkey.PublicKey.KeyIdString() == keyID {
						recipients = append(recipients, k)
					}
				}
			}
		}
	}

	if len(recipients) == 0 {
		log.Fatalf("failed to find any recipients with long key id matched %v", keyIDList)
	}

	secretBuf := bytes.NewBuffer(nil)
	if n, err := io.Copy(secretBuf, os.Stdin); err != nil {
		log.Fatalf("Failed to write encrypted data to the buffer (written %d) %v", n, err)
	}
	secret := &decrypter.Secret{
		Labels: labelList,
		Value:  secretBuf.Bytes(),
	}

	output := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	plaintextWriter, err := openpgp.Encrypt(output, recipients, nil, nil, conf)
	if err != nil {
		log.Fatalf("Failed to open encrypted writer %v", err)
	}
	if err := json.NewEncoder(plaintextWriter).Encode(secret); err != nil {
		log.Fatalf("Failed to write encrypted data: %v", err)
	}

	if err := plaintextWriter.Close(); err != nil {
		log.Fatalf("Failed to close plaintext writer: %v", err)
	}
	if err := output.Close(); err != nil {
		log.Fatalf("Failed to close output: %v", err)
	}
}
