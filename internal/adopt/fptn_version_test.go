package adopt

import "testing"

func TestFPTNImageVersion(t *testing.T) {
	digests := []string{"fptnvpn/fptn-vpn-server@sha256:6711f36d81fe0e860ca56d66d43a5730d8d4e7a2880a3a2bda8f02c81ba5ca55"}
	for _, c := range []struct{ image, want string }{
		{"fptnvpn/fptn-vpn-server:latest", "@sha256:6711f36d81fe0e860ca56d66d43a5730d8d4e7a2880a3a2bda8f02c81ba5ca55"},
		{"fptnvpn/fptn-vpn-server", "@sha256:6711f36d81fe0e860ca56d66d43a5730d8d4e7a2880a3a2bda8f02c81ba5ca55"},
		{"fptnvpn/fptn-vpn-server:0.4.5", "0.4.5"},
		{"fptnvpn/fptn-vpn-server@sha256:abc", "@sha256:abc"},
		{"registry.local:5000/fptnvpn/fptn-vpn-server", "@sha256:6711f36d81fe0e860ca56d66d43a5730d8d4e7a2880a3a2bda8f02c81ba5ca55"},
	} {
		if got := fptnImageVersion(dockerC{Image: c.image}, digests); got != c.want {
			t.Errorf("%s: %q, want %q", c.image, got, c.want)
		}
	}
	if got := fptnImageVersion(dockerC{Image: "fptnvpn/fptn-vpn-server:latest"}, nil); got != "" {
		t.Errorf("без дайджеста: %q", got)
	}
}

func TestParseDockerInspectImageID(t *testing.T) {
	c := parseDockerInspect(`[{"Id":"c1","Name":"/x","Image":"sha256:img","Config":{"Image":"fptnvpn/fptn-vpn-server:latest"}}]`)
	if len(c) != 1 || c[0].ImageID != "sha256:img" {
		t.Fatalf("%+v", c)
	}
}
