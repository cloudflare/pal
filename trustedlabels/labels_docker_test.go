package trustedlabels

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestIsTrusted(t *testing.T) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), fmt.Sprintf("trust-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	d, err := NewDocker("", tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	expectedDigest := "dqminh/pal@sha256:97ad6be16f4a8181510b979cb70f0f825cc2f1065d01b41552c1a3b8f8e96aee"
	trusted, err := d.isTrusted("dqminh/pal:client-integration", expectedDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatalf("image should be trusted (digest: %s) but not", expectedDigest)
	}
}
