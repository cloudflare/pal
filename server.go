package pal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/cloudflare/pal/decrypter"
	"github.com/cloudflare/pal/log"
	"github.com/cloudflare/pal/trustedlabels"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

// ServerConfigEntry represents a parsed PAL server YAML configuration entry.
// Note that this is not the schema for a PAL server YAML configuration file.
// Instead, a PAL server YAML configuration file is itself a map where the keys
// are environment names, and each value is a single entry (represented by this
// type). In other words, the full parsed config file is represented by
// map[string]*ServerConfigEntry
//
// The following is an example configuration file:
//  dev:
//    entrypoint: env
//    env:
//      TESTVAR: ro:4VUfu2xX0KGcvRmP76e4VkdESQziR1S4kh7/TRoNOVJ
type ServerConfigEntry struct {
	ROServer string `yaml:"roserver,omitempty"`
	CABundle string `yaml:"ca,omitempty"`
	User     string `yaml:"ro_user,omitempty"`
	Password string `yaml:"ro_password,omitempty"`

	PGPKeyRingPath string `yaml:"pgp_keyring_path,omitempty"`
	PGPCipher      string `yaml:"pgp_cypher,omitempty"`
	PGPPassphrase  string `yaml:"pgp_passphrase,omitempty"`
	PGPHash        string `yaml:"pgp_hash,omitempty"`

	LabelsEnabled     bool   `yaml:"labels_enabled,omitempty"`
	LabelsRetriever   string `yaml:"labels_retriever,omitempty"`
	NotaryTrustServer string `yaml:"notary_trust_server,omitempty"`
	NotaryTrustDir    string `yaml:"notary_trust_dir,omitempty"`
}

// Server represents a PAL server capable of servicing deryption requests. It
// provides the core functionality for the 'pald' daemon.
type Server struct {
	counter         *prometheus.CounterVec
	labelsRetriever trustedlabels.Retriever
	decrypters      map[string]decrypter.Decrypter
}

// LoadServerConfigEntry reads and parses r as a PAL server YAML configuration
// file, and returns the entry corresponding to the given environment name.
func LoadServerConfigEntry(r io.Reader, environment string) (*ServerConfigEntry, error) {
	configs := make(map[string]*ServerConfigEntry)

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

// NewServer constructs a new Server that supports versions 1 and 2 of the PAL
// protocol.
func NewServer(config *ServerConfigEntry) (s *Server, err error) {
	decrypters := make(map[string]decrypter.Decrypter)
	if config.ROServer != "" {
		roDecrypter, err := decrypter.NewRODecrypter(config.User, config.Password,
			config.ROServer, config.CABundle)
		if err != nil {
			return nil, err
		}
		decrypters["ro"] = roDecrypter
	}
	if config.PGPKeyRingPath != "" {
		pgpDecrypter, err := decrypter.NewPGPDecrypter(config.PGPCipher, config.PGPHash,
			config.PGPKeyRingPath, config.PGPPassphrase)
		if err != nil {
			return nil, err
		}
		decrypters["pgp"] = pgpDecrypter
	}
	if len(decrypters) == 0 {
		return nil, fmt.Errorf("not found any valid decrypter configuration")
	}

	s = &Server{
		decrypters: decrypters,
		counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "decryptions",
			Help: "Decryption requests by label",
		}, []string{"label"}),
	}

	if config.LabelsEnabled {
		switch config.LabelsRetriever {
		case "docker":
			s.labelsRetriever, err = trustedlabels.NewDocker(config.NotaryTrustServer, config.NotaryTrustDir)
			if err != nil {
				return nil, err
			}
		case "mocker":
			// do nothing. We assumes that tests will replace the retriever
		default:
			return nil, fmt.Errorf("invalid labels retriever %s", config.LabelsRetriever)
		}
	}

	if !testMode {
		prometheus.MustRegister(s.counter)
	}
	return s, nil
}

// ServeHTTP serves the legacy version 1 of the PAL protocol. It is only capable
// of handling Red October decryption requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Could not read request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var dreq decryptionRequest
	if err = json.Unmarshal(body, &dreq); err != nil {
		log.Errorf("Could not unmarshal JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var dresp decryptionResponse
	dresp.Secrets = make(map[string]string)
	for k, encryptedBlob := range dreq.Ciphertexts {
		data, err := base64.StdEncoding.DecodeString(encryptedBlob)
		if err != nil {
			log.Errorf("Error decoding base64-encoded secret: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		roDecrypter, ok := s.decrypters["ro"]
		if !ok {
			log.Error("RO decryter not found. Legacy flow is not supported")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		secret, err := roDecrypter.Decrypt(bytes.NewBuffer(data))
		if err != nil {
			log.Errorf("Decryption request to Red October failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			e := decryptionErrorV1{
				Code:   101,
				Err:    err.Error(),
				Secret: k,
			}
			jsonBytes, jsonErr := json.Marshal(e)
			if jsonErr != nil {
				log.Errorf("Failed to marshal error bytes: %v", err)
			}
			w.Write(jsonBytes)
			return
		}
		// NB - this assumes all secrets have been safely
		// encoded for stringification, but the client is
		// guaranteeing that for us.
		dresp.Secrets[k] = string(secret.Value)
	}
	jsonData, err := json.Marshal(dresp)
	if err != nil {
		log.Errorf("Failed to marshal decryption response: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write(jsonData)
}

// ServeRPC serves version 2 of the PAL protocol.
func (s *Server) ServeRPC(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		ucred, err := getUcred(c)
		if err != nil {
			resp := decryptionResponse{
				Error: &decryptionError{
					Code:    101,
					Message: fmt.Sprintf("failed to retrieve peer credential of the connection: %v", err),
				},
			}
			if err := json.NewEncoder(c).Encode(&resp); err != nil {
				log.Errorf("Failed to send error response: %v", err)
			}
			c.Close()
			continue
		}
		go s.serveRPCConn(&conn{
			Conn:  c,
			Ucred: ucred,
		})
	}
}

func (s *Server) serveRPCConn(c *conn) {
	decoder := json.NewDecoder(c)
	encoder := json.NewEncoder(c)

	defer func() {
		if err := c.Close(); err != nil {
			log.Infof("failed to close connection: %v", err)
		}
	}()

	var (
		authorizedLabels map[string]struct{}
		err              error
	)
	if s.labelsRetriever != nil {
		authorizedLabels, err = s.labelsRetriever.LabelsForPID(int(c.Pid))
		if err != nil {
			writeDecryptionError(encoder, 101, fmt.Sprintf("failed to get authorized labels: %v", err), "")
			return
		}
	}

	var dreq decryptionRequest
	if err := decoder.Decode(&dreq); err != nil {
		writeDecryptionError(encoder, 101, fmt.Sprintf("Could not unmarshal JSON: %v", err), "")
		return
	}
	var dresp decryptionResponse
	dresp.Secrets = make(map[string]string)

	for k, v := range dreq.Ciphertexts {
		decrypterType, b64, encryptedBlob := decrypter.SplitPALValue(v)
		// Always base64-decode the ciphertext to get something parsable
		data, err := base64.StdEncoding.DecodeString(encryptedBlob)
		if err != nil {
			writeDecryptionError(encoder, 101, fmt.Sprintf("Error decoding base64-encoded secret: %v", err), "")
		}

		secret, err := s.decrypters[decrypterType].Decrypt(bytes.NewBuffer(data))
		if err != nil {
			writeDecryptionError(encoder, 101, fmt.Sprintf("Failed to decrypt secret: %v", err), "")
			return
		}

		for _, label := range secret.Labels {
			s.counter.WithLabelValues(label).Inc()
			if _, ok := authorizedLabels[label]; !ok && s.labelsRetriever != nil {
				writeDecryptionError(encoder, 101, fmt.Sprintf("Error unauthorized label: %s, required %v", label, authorizedLabels), "")
				return
			}
		}

		// NB - this assumes all secrets have been safely encoded for
		// stringification, but the client is guaranteeing that for us.
		dresp.Secrets[k] = string(secret.Value)
		if b64 {
			dresp.Secrets[k] = "base64:" + dresp.Secrets[k]
		}
	}

	if err := encoder.Encode(dresp); err != nil {
		log.Errorf("Failed to marshal decryption response: %v", err)
	}
}

func writeDecryptionError(w *json.Encoder, code int, msg string, secret string) {
	log.Error(msg)
	resp := decryptionResponse{
		Error: &decryptionError{
			Code:    101,
			Message: msg,
			Secret:  secret,
		},
	}
	if err := w.Encode(&resp); err != nil {
		log.Errorf("Failed to send error response: %v", err)
	}
}
