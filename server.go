package pal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"syscall"

	yaml "gopkg.in/yaml.v2"

	"github.com/cloudflare/pal/decrypter"
	"github.com/cloudflare/pal/trustedlabels"
	"github.com/cloudflare/redoctober/cryptor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/uber-go/zap"
)

// ServerConfig contains the valid configuration for PAL daemon.
type ServerConfig struct {
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

// Server is the PAL daemon. It is responsible for verifying client identity
// and decrypting their secrets.
type Server struct {
	logger          zap.Logger
	counter         *prometheus.CounterVec
	labelsRetriever trustedlabels.Retriever
	decrypters      map[string]decrypter.Decrypter
}

// LoadServerConfig returns the server configuration given yaml configuration
// data and the server environment.
func LoadServerConfig(r io.Reader, environment string) (*ServerConfig, error) {
	configs := make(map[string]*ServerConfig)

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

// NewServer returns a configured server given its configuration. It returns an
// error if it failed to configure a chosen decrypter, or doesnt have any
// configured decrypters, or failed to configure the labels retriever to verify
// client identity.
func NewServer(logger zap.Logger, config *ServerConfig) (s *Server, err error) {
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
		logger:     logger,
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

	prometheus.MustRegister(s.counter)
	return s, nil
}

// ServeRPC starts the request loop to accept client decryption requests.
func (s *Server) ServeRPC(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		ucred, err := getUnixCred(conn)
		if err != nil {
			resp := decryptionResponse{
				Error: &errorMsg{
					Code:    101,
					Message: fmt.Sprintf("failed to retrieve peer credential of the connection: %v", err),
				},
			}
			if err := json.NewEncoder(conn).Encode(&resp); err != nil {
				s.logger.Error("failed to send error response", zap.Error(err))
			}
			conn.Close()
			continue
		}
		go s.serveRPCConn(&credConn{
			Conn:  conn,
			Ucred: ucred,
		})
	}
}

func (s *Server) serveRPCConn(c *credConn) {
	decoder := json.NewDecoder(c)
	encoder := json.NewEncoder(c)

	defer func() {
		if err := c.Close(); err != nil {
			s.logger.Info("failed to close connection", zap.Error(err))
		}
	}()

	var (
		authorizedLabels map[string]struct{}
		err              error
	)
	if s.labelsRetriever != nil {
		authorizedLabels, err = s.labelsRetriever.LabelsForPID(int(c.Pid))
		if err != nil {
			s.writeDecryptionError(encoder, 101, fmt.Sprintf("failed to get authorized labels: %v", err), "")
			return
		}
	}

	var dreq decryptionRequest
	if err := decoder.Decode(&dreq); err != nil {
		s.writeDecryptionError(encoder, 101, fmt.Sprintf("Could not unmarshal JSON: %v", err), "")
		return
	}
	var dresp decryptionResponse
	dresp.Secrets = make(map[string]string)

	for k, v := range dreq.Ciphertexts {
		decrypterType, binary, encryptedBlob := decrypter.SplitPALValue(v)
		// Always base64-decode the ciphertext to get something parsable
		data, err := base64.StdEncoding.DecodeString(encryptedBlob)
		if err != nil {
			s.writeDecryptionError(encoder, 101, fmt.Sprintf("Error decoding base64-encoded secret: %v", err), "")
		}

		secret, err := s.decrypters[decrypterType].Decrypt(bytes.NewBuffer(data))
		if err != nil {
			s.writeDecryptionError(encoder, 101, fmt.Sprintf("Failed to decrypt secret: %v", err), "")
			return
		}

		for _, label := range secret.Labels {
			s.counter.WithLabelValues(label).Inc()
			if _, ok := authorizedLabels[label]; !ok && s.labelsRetriever != nil {
				s.writeDecryptionError(encoder, 101, fmt.Sprintf("Error unauthorized label: %s, required %v", label, authorizedLabels), "")
				return
			}
		}

		// NB - this assumes all secrets have been safely
		// encoded for stringification, but the client is
		// guaranteeing that for us.
		dresp.Secrets[k] = decrypter.JoinPalValue(binary, string(secret.Value))
	}

	if err := encoder.Encode(dresp); err != nil {
		s.logger.Error("failed to send decryption response", zap.Error(err))
	}
}

func (s *Server) writeDecryptionError(w *json.Encoder, code int, msg string, secret string) {
	s.logger.Error(msg)
	resp := decryptionResponse{
		Error: &errorMsg{
			Code:    101,
			Message: msg,
			Secret:  secret,
		},
	}
	if err := w.Encode(&resp); err != nil {
		s.logger.Error("failed to send error response", zap.Error(err))
	}
}

// credConn holds the current connection together with its unix credential
type credConn struct {
	net.Conn
	*syscall.Ucred
}

// getUnixCred gets the unix credentials from the unix network connection
func getUnixCred(conn net.Conn) (*syscall.Ucred, error) {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("internal listener is not a net.UnixListener")
	}
	f, err := uconn.File()
	if err != nil {
		return nil, err
	}
	return syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}

func parseEncryptedData(data []byte) ([]byte, error) {
	ed := new(cryptor.EncryptedData)
	if err := json.Unmarshal(data, ed); err != nil {
		return nil, err
	}
	return ed.Data, nil
}

func parseROLabel(data []byte) (string, error) {
	ed := new(cryptor.EncryptedData)
	if err := json.Unmarshal([]byte(data), ed); err != nil {
		return "", err
	}
	if len(ed.Labels) > 0 {
		return ed.Labels[0], nil
	}
	return "", nil
}
