package pal

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/pal/trustedlabels"
	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"github.com/joshlf/testutil"
)

const (
	adminUser, adminPass = "admin-user", "admin-password"
	paldUser, paldPass   = "pald-user", "pald-password"
	aliceUser, alicePass = "alice", "alice-password"
	bobUser, bobPass     = "bob", "bob-password"
	plainSecret          = "i am a plain secret"
	testLabel            = "test-label"
)

var (
	base64Secret        = string(base64.StdEncoding.EncodeToString([]byte("i am a base64 encoded secret")))
	mockLabelsRetriever = trustedlabels.NewMock(
		map[string]struct{}{
			"app-foo":     {},
			"test-secret": {},
		},
	)
)

// returns the listener and the temporary directory that was created to contain
// it; the listener should be closed and the directory deleted when finished
func mustListenUnixSocket(t *testing.T) (net.Listener, string) {
	tempdir := testutil.MustTempDir(t, "", "pal-test")
	l, err := net.Listen("unix", filepath.Join(tempdir, "pald.sock"))
	testutil.MustPrefix(t, "could not listen on unix socket", err)
	return l, tempdir
}

type roTestInstance struct {
	tempdir    string
	cert       string
	server     *roServer
	serverAddr string
	client     *client.RemoteServer
}

func mustROTestInstance(t *testing.T) *roTestInstance {
	tempdir := testutil.MustTempDir(t, "", "pal-ro-test")
	cert := testutil.MustWriteTempFile(t, tempdir, "", roCert)
	key := testutil.MustWriteTempFile(t, tempdir, "", roKey)
	vault := filepath.Join(tempdir, "test.vaul")

	// Choose random ports for both the client communication and the metrics so
	// that we minimize the probability of a port collision that would  cause
	// redoctober to fail to start. This is certainly a hack, but it's a hack that
	// works well enough.
	randPort := func() int { return rand.New(rand.NewSource(time.Now().UnixNano())).Intn((1<<16)-1024) + 1024 }
	port := randPort()
	metricsPort := randPort()
	addr := fmt.Sprintf("localhost:%v", port)
	server := mustROServer(t, vault, cert, key, addr, strconv.Itoa(metricsPort))
	// we set this to false just before returning; if it's still true in the
	// defered func, we must be panicking
	panicking := true
	defer func() {
		if panicking {
			server.Quit(t)
		}
	}()

	client, err := client.NewRemoteServer(addr, cert)
	testutil.MustPrefix(t, "could not create redoctober client", err)

	create := func(user, pass string) {
		_, err := client.CreateUser(core.CreateUserRequest{Name: user, Password: pass})
		testutil.MustPrefix(t, fmt.Sprintf("could not create Red October user %v", user), err)
	}
	// Create creates an admin user, while CreateUser creates a normal user
	_, err = client.Create(core.CreateRequest{Name: adminUser, Password: adminPass})
	testutil.MustPrefix(t, fmt.Sprintf("could not create Red October admin %v", adminUser), err)
	create(paldUser, paldPass)
	create(aliceUser, alicePass)
	create(bobUser, bobPass)

	panicking = false
	return &roTestInstance{
		tempdir:    tempdir,
		cert:       cert,
		server:     server,
		serverAddr: addr,
		client:     client,
	}
}

// Encrypts the given secret with the given encryptLabels for both alice and bob
// with a minimum of two delegations. Then, alice and bob each delegate for
// delegateLabels.
func (r *roTestInstance) mustEncryptAndDelegate(t *testing.T, secret string,
	encryptLabels, delegateLabels []string) string {
	ereq := core.EncryptRequest{
		Name:     aliceUser,
		Password: alicePass,

		Owners:  []string{aliceUser, bobUser},
		Data:    []byte(secret),
		Labels:  encryptLabels,
		Minimum: 2,
	}

	eres, err := r.client.Encrypt(ereq)
	testutil.MustPrefix(t, "could not encrypt secret", err)

	dr := core.DelegateRequest{
		Name:     aliceUser,
		Password: alicePass,
		Uses:     1000000,
		Time:     "100h",
		Users:    []string{paldUser},
		Labels:   delegateLabels,
	}

	_, err = r.client.Delegate(dr)
	testutil.MustPrefix(t, "could not delegate", err)

	dr = core.DelegateRequest{
		Name:     bobUser,
		Password: bobPass,
		Uses:     1000000,
		Time:     "100h",
		Users:    []string{paldUser},
		Labels:   delegateLabels,
	}

	_, err = r.client.Delegate(dr)
	testutil.MustPrefix(t, "could not delegate", err)

	return base64.StdEncoding.EncodeToString(eres.Response)
}

func (r *roTestInstance) Quit(t *testing.T) {
	err := os.RemoveAll(r.tempdir)
	if err != nil {
		t.Logf("warning: could not remove temporary directory: %v", err)
	}
	r.server.Quit(t)
}

type roServer struct {
	cmd *exec.Cmd
}

func mustROServer(t *testing.T, vaultPath, certPath, keyPath, addr, metricsPort string) *roServer {
	binpath, err := exec.LookPath("redoctober")
	testutil.MustPrefix(t, "could not find 'redoctober' program", err)

	cmd := exec.Command(binpath, "-vaultpath", vaultPath, "-certs", certPath, "-keys",
		keyPath, "-addr", addr, "-metrics-port", metricsPort)
	err = cmd.Start()
	testutil.MustPrefix(t, "could not run 'redoctober'", err)

	// Give redoctober time to start so that API requests won't get there before
	// it's listening.
	time.Sleep(time.Second)

	return &roServer{cmd}
}

func (r *roServer) Quit(t *testing.T) {
	err := r.cmd.Process.Kill()
	if err != nil {
		t.Logf("warning: could not kill 'redoctober' process: %v", err)
	}
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
