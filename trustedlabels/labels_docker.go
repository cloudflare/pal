package trustedlabels

import (
	"context"
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

	"github.com/cloudflare/pal/log"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	// "github.com/docker/engine-api/types"
	"github.com/docker/go-connections/tlsconfig"
	notary "github.com/docker/notary/client"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf/data"
	"github.com/moby/moby/api/types"
	"github.com/moby/moby/client"
	"github.com/moby/moby/registry"
	// "github.com/opencontainers/go-digest"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

var (
	dockerCgroupRegexp = regexp.MustCompile(`([[:xdigit:]]{64})`)
	trustedReleaseRole = path.Join(string(data.CanonicalTargetsRole), "releases")
	palLabel           = "pal.labels"

	// ErrUnknownContainer is the error used when a Docker container could not be
	// identified.
	ErrUnknownContainer = errors.New("unknown docker container")
)

type docker struct {
	trustServer  string
	trustBaseDir string
	dockerClient *client.Client
}

// NewDocker returns a new Retriever that uses the provided notary server and
// trust store base directory to look up labels in the Docker daemon and then
// validate the associated images' cryptographic signatures.
func NewDocker(trustServer string, trustBaseDir string) (Retriever, error) {
	if trustServer == "" {
		trustServer = registry.NotaryServer
	}
	if trustBaseDir == "" {
		trustBaseDir = ".trust"
	}
	c, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	return &docker{
		trustServer:  trustServer,
		trustBaseDir: trustBaseDir,
		dockerClient: c,
	}, nil
}

func (d *docker) LabelsForPID(pid int) (map[string]struct{}, error) {
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

func (d *docker) isTrusted(imageName string, localDigest string) (bool, error) {
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

func (d *docker) trustedReference(name string) (reference.Canonical, error) {
	ref, err := reference.ParseNamed(name)
	if err != nil {
		return nil, err
	}
	namedTagged, ok := ref.(reference.NamedTagged)
	if !ok {
		namedTagged, err = reference.WithTag(ref, "latest")
		if err != nil {
			// "latest" tag is guaranteed to be valid
			panic(err)
		}
		// namedTagged = reference.WithDefaultTag(ref).(reference.NamedTagged)
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
		return nil, fmt.Errorf("failed %v: %v", repoInfo.Name, fmt.Errorf("No trust data for %s", namedTagged.Tag()))
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
func (d *docker) notaryRepository(repoInfo *registry.RepositoryInfo, authConfig types.AuthConfig, actions ...string) (*notary.NotaryRepository, error) {
	var cfg = tlsconfig.ClientDefault
	cfg.InsecureSkipVerify = !repoInfo.Index.Secure

	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &cfg,
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

	challengeManager := challenge.NewSimpleManager()

	resp, err := pingClient.Do(req)
	if err != nil {
		// Ignore error on ping to operate in offline mode
		log.Debugf("Error pinging notary server %q: %s", endpointStr, err)
	} else {
		defer resp.Body.Close()
		// Add response to the challenge manager to parse out
		// authentication header and register authentication method
		if err := challengeManager.AddResponse(resp); err != nil {
			return nil, err
		}
	}

	creds := simpleCredentialStore{auth: authConfig}
	tokenHandler := auth.NewTokenHandler(authTransport, creds, repoInfo.Name.String(), actions...)
	basicHandler := auth.NewBasicHandler(creds)
	modifiers = append(modifiers, transport.RequestModifier(auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler)))
	tr := transport.NewTransport(base, modifiers...)

	return notary.NewFileCachedNotaryRepository(d.trustBaseDir, repoInfo.Name.String(), d.trustServer, tr, nil, trustpinning.TrustPinConfig{})
}

type target struct {
	reference reference.Reference
	digest    digest.Digest
	size      int64
}

func convertTarget(t notary.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	ref, err := reference.Parse(t.Name)
	if err != nil {
		return target{}, fmt.Errorf("error parsing reference: %s", err)
	}

	return target{
		reference: ref,
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
