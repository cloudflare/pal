package trustedlabels

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	docker "github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docker/notary/client"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf/data"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

var (
	// ErrUnknownContainer is the error returned when we can not determine the
	// container of the process.
	ErrUnknownContainer = errors.New("unknown docker container")

	dockerCgroupRegexp = regexp.MustCompile(`([[:xdigit:]]{64})`)
	trustedReleaseRole = path.Join(data.CanonicalTargetsRole, "releases")
	palLabel           = "pal.labels"
)

// Docker implements Retriever interface for a Docker container which image was
// managed by Notary.
type Docker struct {
	trustServer  string
	trustBaseDir string
	dockerClient *docker.Client
}

// NewDocker returns the Docker Retriever given the Notary trust server and a
// path to local filesystem for trust data storage.
func NewDocker(trustServer string, trustBaseDir string) (*Docker, error) {
	if trustServer == "" {
		trustServer = registry.NotaryServer
	}
	if trustBaseDir == "" {
		trustBaseDir = ".trust"
	}
	c, err := docker.NewEnvClient()
	if err != nil {
		return nil, err
	}
	return &Docker{
		trustServer:  trustServer,
		trustBaseDir: trustBaseDir,
		dockerClient: c,
	}, nil
}

// LabelsForPID returns the trusted labels of the container's image given a
// process's PID inside the container.
func (d *Docker) LabelsForPID(pid int) (map[string]struct{}, error) {
	cgs, err := cgroups.ParseCgroupFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return nil, err
	}

	var containerID string
	for _, id := range cgs {
		if matches := dockerCgroupRegexp.FindStringSubmatch(id); matches != nil {
			containerID = matches[1]
			break
		}
	}
	if containerID == "" {
		return nil, ErrUnknownContainer
	}

	ctx := context.Background()
	container, err := d.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}

	image, _, err := d.dockerClient.ImageInspectWithRaw(ctx, container.Image)
	if err != nil {
		return nil, err
	}
	if len(image.RepoTags) < 1 || len(image.RepoDigests) < 1 {
		return nil, errors.New("image without tag or digests")
	}

	trusted, err := d.isTrusted(image.RepoTags[0], image.RepoDigests[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get trust status: %v", err)
	}
	if !trusted {
		return nil, fmt.Errorf("image %s with digest %v is not trusted", image.RepoTags[0], image.RepoDigests)
	}

	labels := make(map[string]struct{})
	if v, ok := image.Config.Labels[palLabel]; ok {
		for _, label := range strings.Split(v, ",") {
			labels[strings.TrimSpace(label)] = struct{}{}
		}
	}
	return labels, nil
}

func (d *Docker) isTrusted(imageName string, localDigest string) (bool, error) {
	ref, err := d.trustedReference(imageName)
	if err != nil {
		return false, err
	}
	remoteDigest := ref.Digest().String()
	// local repoDigest format of name@digest
	if arr := strings.SplitN(localDigest, "@", 2); len(arr) == 2 {
		return remoteDigest == arr[1], nil
	}
	return remoteDigest == localDigest, nil
}

func (d *Docker) trustedReference(name string) (reference.Canonical, error) {
	ref, err := reference.ParseNamed(name)
	if err != nil {
		return nil, err
	}
	namedTagged, ok := ref.(reference.NamedTagged)
	if !ok {
		namedTagged = reference.WithDefaultTag(ref).(reference.NamedTagged)
	}

	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return nil, err
	}
	notaryRepo, err := d.notaryRepository(repoInfo, types.AuthConfig{}, "pull")
	if err != nil {
		return nil, err
	}

	t, err := notaryRepo.GetTargetByName(namedTagged.Tag(), trustedReleaseRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, err
	}

	// Only list tags in the top level targets role or the releases delegation role
	// ignore all other delegation roles
	if t.Role != trustedReleaseRole && t.Role != data.CanonicalTargetsRole {
		return nil, fmt.Errorf("failed %s: %v", repoInfo.FullName(), fmt.Errorf("No trust data for %s", namedTagged.Tag()))
	}

	r, err := convertTarget(t.Target)
	if err != nil {
		return nil, err

	}
	return reference.WithDigest(namedTagged, r.digest)
}

// notaryRepository returns a NotaryRepository which stores all the
// information needed to operate on a notary repository.
// It creates an HTTP transport providing authentication support.
func (d *Docker) notaryRepository(repoInfo *registry.RepositoryInfo, authConfig types.AuthConfig, actions ...string) (*client.NotaryRepository, error) {
	cfg := &tls.Config{
		// Prefer TLS1.2 as the client minimum
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: !repoInfo.Index.Secure,
	}

	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     cfg,
		DisableKeepAlives:   true,
	}

	// Skip configuration headers since request is not going to Docker daemon
	modifiers := registry.DockerHeaders("notarytrust/agent", http.Header{})
	authTransport := transport.NewTransport(base, modifiers...)
	pingClient := &http.Client{
		Transport: authTransport,
		Timeout:   5 * time.Second,
	}
	endpointStr := d.trustServer + "/v2/"
	req, err := http.NewRequest("GET", endpointStr, nil)
	if err != nil {
		return nil, err
	}

	challengeManager := auth.NewSimpleChallengeManager()

	resp, err := pingClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Add response to the challenge manager to parse out
	// authentication header and register authentication method
	if err := challengeManager.AddResponse(resp); err != nil {
		return nil, err
	}

	creds := simpleCredentialStore{auth: authConfig}
	tokenHandler := auth.NewTokenHandler(authTransport, creds, repoInfo.FullName(), actions...)
	basicHandler := auth.NewBasicHandler(creds)
	modifiers = append(modifiers, transport.RequestModifier(auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler)))
	tr := transport.NewTransport(base, modifiers...)

	return client.NewFileCachedNotaryRepository(d.trustBaseDir, repoInfo.FullName(), d.trustServer, tr, nil, trustpinning.TrustPinConfig{})
}

type target struct {
	reference registry.Reference
	digest    digest.Digest
	size      int64
}

func convertTarget(t client.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	return target{
		reference: registry.ParseReference(t.Name),
		digest:    digest.NewDigestFromHex("sha256", hex.EncodeToString(h)),
		size:      t.Length,
	}, nil
}

func trustServer() string {
	return registry.NotaryServer
}

type simpleCredentialStore struct {
	auth types.AuthConfig
}

func (scs simpleCredentialStore) Basic(u *url.URL) (string, string) {
	return scs.auth.Username, scs.auth.Password
}

func (scs simpleCredentialStore) RefreshToken(u *url.URL, service string) string {
	return scs.auth.IdentityToken
}

func (scs simpleCredentialStore) SetRefreshToken(*url.URL, string, string) {}
