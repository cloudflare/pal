package pal

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/pal/trustedlabels"
	ro "github.com/cloudflare/redoctober"
	"github.com/cloudflare/redoctober/client"
	roConfig "github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/core"
	"github.com/uber-go/zap"
)

var (
	cert, key = tempFile(roCert), tempFile(roKey)

	serverConfig = &ServerConfig{
		ROServer:        strings.TrimPrefix(mustROServer(cert, key).URL, "https://"),
		LabelsRetriever: "mocker",
		CABundle:        cert,
		User:            paldUser,
		Password:        paldPass,
	}
	server *Server

	paldUser, paldPass   = "pald-user", "pald-password"
	aliceUser, alicePass = "alice", "alice-password"
	bobUser, bobPass     = "bob", "bob-password"

	plainSecret  = "i am a plain secret"
	base64Secret = string(base64.StdEncoding.EncodeToString([]byte("i am a base64 encoded secret")))

	plainCipherText, base64CipherText string

	mockLabelsRetriever = trustedlabels.NewMocker(
		map[string]struct{}{
			"app-foo":     {},
			"test-secret": {},
		},
	)

	logger = zap.New(zap.NewTextEncoder())
)

func init() {
	roServer, err := client.NewRemoteServer(serverConfig.ROServer, serverConfig.CABundle)
	if err != nil {
		panic(err)
	}

	if _, err = roServer.Create(core.CreateRequest{Name: "test-admin", Password: "test-passwd"}); err != nil {
		panic(err)
	}
	if _, err = roServer.CreateUser(core.CreateUserRequest{Name: paldUser, Password: paldPass}); err != nil {
		panic(err)
	}
	if _, err = roServer.CreateUser(core.CreateUserRequest{Name: aliceUser, Password: alicePass}); err != nil {
		panic(err)
	}
	if _, err = roServer.CreateUser(core.CreateUserRequest{Name: bobUser, Password: bobPass}); err != nil {
		panic(err)
	}

	plainCipherText = mustEncrypt(plainSecret, []string{"test-secret"})
	base64CipherText = mustEncrypt(base64Secret, []string{"test-secret"})
	server, err = NewServer(logger, serverConfig)
	if err != nil {
		panic(fmt.Sprintf("failed to initialized new server %v", err))
	}
	server.labelsRetriever = mockLabelsRetriever
}

func TestServer(t *testing.T) {
	const nopSecret = "nom nom nom"

	addr := socketPath()
	listener, err := net.Listen("unix", addr)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	go func() {
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	cfg := &config{
		Envs: map[string]string{
			"NOP":   nopSecret,
			"PLAIN": "ro:" + plainCipherText,
			"B64":   "ro+base64:" + base64CipherText,
		},
		Files: map[string]string{
			"/path/to/nop":   nopSecret,
			"/path/to/plain": "ro:" + plainCipherText,
			"/path/to/b64":   "ro+base64:" + base64CipherText,
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := newClient(cfg, addr)
	if err := client.Decrypt(); err != nil {
		t.Fatal(err)
	}

	if got := client.config.Envs["NOP"]; got != nopSecret {
		t.Errorf("want ro: secret %q, got %q", nopSecret, got)
	}
	if got := client.config.Files["/path/to/nop"]; got != nopSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
	if got := client.config.Envs["PLAIN"]; got != plainSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
	if got := client.config.Files["/path/to/plain"]; got != plainSecret {
		t.Errorf("want ro: secret %q, got %q", plainSecret, got)
	}
	if got := client.config.Envs["B64"]; got != "base64:"+base64Secret {
		t.Errorf("want ro+base64: secret %q, got %q", "base64:"+base64Secret, got)
	}
	if got := client.config.Files["/path/to/b64"]; got != "base64:"+base64Secret {
		t.Errorf("want ro+base64: secret %q, got %q", "base64:"+base64Secret, got)
	}
}

func TestServerWithInvalidLabel(t *testing.T) {
	addr := socketPath()
	listener, err := net.Listen("unix", addr)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	go func() {
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	cfg := &config{
		Envs: map[string]string{
			"PLAIN": "ro:" + mustEncrypt(plainSecret, []string{"required-label-but-not-exist"}),
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := newClient(cfg, addr)
	if err := client.Decrypt(); err == nil {
		t.Fatal("want unauthorized label error, got nil")
	}
}

func TestServerWithoutPeerCred(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	go func() {
		err := server.ServeRPC(listener)
		if err != nil {
			t.Log(err)
		}
	}()

	cfg := &config{
		Envs: map[string]string{
			"B64": "ro+base64:" + base64CipherText,
		},
		EntryPoint: "env -t /foo/bar.tmpl:/foo/bar -E",
		Command:    "true -entrypoint-flag=foo --",
	}

	client := &Client{
		socketAddr: listener.Addr().String(),
		config:     cfg,
		dialFunc: func(_, _ string) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
	}
	if err := client.Decrypt(); err == nil {
		t.Fatal("expected error when calling RPC with a TCP connection but got nil")
	}
}

func socketPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("pal-test-%d.sock", time.Now().UnixNano()))
}

func mustROServer(cert, key string) *httptest.Server {
	vaultPath, err := ioutil.TempDir("", "ro")
	if err != nil {
		panic(err)
	}
	vaultPath += "test.vault"

	if err := core.Init(vaultPath, &roConfig.Config{
		HipChat:     &roConfig.HipChat{},
		Delegations: &roConfig.Delegations{},
	}); err != nil {
		panic(err)
	}

	roCerts, roKeys := []string{cert}, []string{key}

	s, _, err := ro.NewServer(vaultPath, "", "", roCerts, roKeys, false)
	if err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	cfg := &tls.Config{
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
	for i, certPath := range roCerts {
		cert, err := tls.LoadX509KeyPair(certPath, roKeys[i])
		if err != nil {
			panic(fmt.Errorf("Error loading certificate (%s, %s): %s", certPath, roKeys[i], err))
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}
	cfg.BuildNameToCertificate()

	l = tls.NewListener(l, cfg)

	go s.Serve(l)

	// add provisioning of users via API calls
	// encrypt a secret, return the ciphertext

	port := strings.Split(l.Addr().String(), ":")[1]

	return &httptest.Server{
		Listener: l,
		URL:      "https://localhost:" + port,
	}
}

func mustEncrypt(secret string, labels []string) string {
	roServer, err := client.NewRemoteServer(serverConfig.ROServer, serverConfig.CABundle)
	if err != nil {
		panic(err)
	}

	ereq := core.EncryptRequest{
		Name:     aliceUser,
		Password: alicePass,

		Owners:  []string{aliceUser, bobUser},
		Data:    []byte(secret),
		Labels:  labels,
		Minimum: 2,
	}

	eres, err := roServer.Encrypt(ereq)
	if err != nil {
		panic(err)
	}

	dr := core.DelegateRequest{
		Name:     aliceUser,
		Password: alicePass,
		Uses:     1000000,
		Time:     "100h",
		Users:    []string{paldUser},
		Labels:   labels,
	}

	if _, err := roServer.Delegate(dr); err != nil {
		panic(err)
	}

	dr = core.DelegateRequest{
		Name:     bobUser,
		Password: bobPass,
		Uses:     1000000,
		Time:     "100h",
		Users:    []string{paldUser},
		Labels:   labels,
	}

	if _, err := roServer.Delegate(dr); err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(eres.Response)
}

func tempFile(data []byte) string {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		panic(err)
	}
	if _, err := f.Write(data); err != nil {
		panic(err)
	}

	return f.Name()
}

type mocker struct {
	labels map[string]struct{}
}

func (m mocker) LabelsForPID(int) (map[string]struct{}, error) {
	return m.labels, nil
}

var (
	roKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA465BpC3DkQNeNdwLVJ4OC9mNzr1/aRWsd2KQEEplyTql0Dfl
bS54gHLE9rYsNmAUbHm2UV7T89sLDxK0Fnrb/hJ2x9HzZOu9FcqCAfxeJ/6UiLwl
SQxir8xSzmOljdA62JPtWAgKaMSQ8k8nUJxKYZpWCx/3kYM8w9W73hrBzEAFmnhP
gYv2X+rMIaxy4zW5yc+5nOZi8nhfRrgI8NKZjygsk+xM1oWoEjZHAqBNJjOD+zV0
A97dw2xw4A/ONC6NXuptkXwONk/AeFmghv5p/T42pFSG4dmJRBua9/I7eNTiJ+BP
v8qw0grztRUYkBfQXEklrT2bIwA3IiWjeKKzOwIDAQABAoIBACCxzkVIORQi2q17
Srk89SFofT+Z4Kjzbs+5/JwKQvGRlWwACtcR3EX9tSEEafbo9yXYmIC40FDtPHpO
okO0ItEqT5pEIOJ2I7H0YZTta4vst+Gmuufxel5qRd3TW1uw8jJVk7iXdv8ycuoI
ycl+mAPKCN8SGRfxM5GfqJmtV/T/WyuPieS+8jBscc0tyHOEKRoiXyEZSnHiDVJ/
wTh0AEjbIiKSFNalJ0PiYcVYiAP5KG7/LzFhkq3Qz+j77Jyvup61t8400E8FKgBJ
5F4j1u93hU2GTAJouozG7O8+s8Vb6BV3POB7wgeqZ5T+54gbfelIYqZcMY65gUGK
tRSLbtECgYEA+rYY/96vSIH1+j9wSBVzkCDLZtJD4+uVmXpSF/PLy4ilzwgFX8ZN
aaZvM4BAVt9RH55u0CQ2SHbPXDL6VK3bPPBwhHBaZThUtPhxJXE2tJLh4cvxxmaj
2MRH/OuSj09JyZuBEd6yWECdzXMABIATHGKXibAtvbrjV0O2G+G89LkCgYEA6HvJ
qMwa3XzvnjyqnkTcO5sMnOee8fOWAJ8voE0MqQ+/IqlpGsw24tt6wZVofmIN/HIc
5KdpJWD5hXZGo9yn7pLBOIjkHV4gqj1K9k9qfBCbsQ88fbU2QwYcaxgNqExDG1cM
BVVeBik65nVDf4nGWuTuMMOraMsEsTdAeugHFZMCgYBcnIG1mvvi6+cCTwbaCdqL
hiG81LUxb2furum+YVeJ0ut1A8CAdY9JFKsFOj4KGSotZOgISSgoMoM8yrQALczL
wQG/WoV52Iop45BgRWbw40U/lIe2Q1oJC9CP1DFqcN6P87qE8F+vDAd+yhlakDj/
Bkh2Gzd6W5v5M1EFEaksOQKBgQCLT+J/7A8NOpi8Uc5MGSd/8GGWhJWSl00EAmAf
xwwXIwB+XNZG4KjjOHJPHqEHWurWo+r8efVgGMRtXXrnJorbQ8XVgvJvRsB8Q05w
WxaMUcd6So8NJVHmx/qvkjJc75YnA/qIF6fIOVy6TPqtqnnabeTuA9LrcPzW1S0m
eXQFUQKBgQDtAfhdfHFLi86F6Ug2YffUXg4z3IRS2nvIF7BqPVcesW1C4c9jMfhW
t6iUKoM8Ic3AIz0PCgaPwjNUzQzRBIFhUmYA0lI64ObQVyP6FS7L0/NUyzIQ9vLh
ZSl53lqHGMayvKYTqw+JWxD6hm2sW2AvHfjiZvKojsF/AurlKgv8ZQ==
-----END RSA PRIVATE KEY-----`)

	roCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIJANmFCW69BzgNMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEG
A1UECgwKQ2xvdWRGbGFyZTESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE2MDEyODIy
MjY0MVoXDTI2MDEyNTIyMjY0MVowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB
MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRMwEQYDVQQKDApDbG91ZEZsYXJlMRIw
EAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDjrkGkLcORA1413AtUng4L2Y3OvX9pFax3YpAQSmXJOqXQN+VtLniAcsT2tiw2
YBRsebZRXtPz2wsPErQWetv+EnbH0fNk670VyoIB/F4n/pSIvCVJDGKvzFLOY6WN
0DrYk+1YCApoxJDyTydQnEphmlYLH/eRgzzD1bveGsHMQAWaeE+Bi/Zf6swhrHLj
NbnJz7mc5mLyeF9GuAjw0pmPKCyT7EzWhagSNkcCoE0mM4P7NXQD3t3DbHDgD840
Lo1e6m2RfA42T8B4WaCG/mn9PjakVIbh2YlEG5r38jt41OIn4E+/yrDSCvO1FRiQ
F9BcSSWtPZsjADciJaN4orM7AgMBAAGjUDBOMB0GA1UdDgQWBBQ4Y/Soo1XEqgfP
5AdfYLN6hXjZzTAfBgNVHSMEGDAWgBQ4Y/Soo1XEqgfP5AdfYLN6hXjZzTAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBMs7JX9HrabbWI8AiNAr+VTq9Q
AKx+mqqNQxrI01SvYbQEaoB1macCi9mY7lAHBupKxYd5Y99ewplNN5KsAegdjhLH
MHJD9Ra/rftkyQ5szNjL7fA8H1e0IwyamdJT07i4688Miv7ABCdFYZNKaPIonnXZ
BQ0VTmgszBcqpEdvWMjUP369o8C/ddETRqoFHDevFNj5P2rdVgR16dy5dEBrzOUk
WbCX2LqzIrbDPnA7SM9CUPmBnpl/vm/WTrfX0U5N1LG7SzRSYWELpzXmfv+c0mXn
jXnaA224yYMtzkCBBe/9gfxIvxrF7zFDzRnj6vkroTb1R9LREIaf1/i9klAJ
-----END CERTIFICATE-----`)
)
