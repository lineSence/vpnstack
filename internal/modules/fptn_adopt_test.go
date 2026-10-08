package modules

import (
	"strings"
	"testing"

	"github.com/lineSence/vpnstack/internal/state"
)

func fptnTestSvc(t *testing.T, params map[string]string) (*FPTN, *state.Service) {
	t.Helper()
	f := &FPTN{base{id: "fptn"}}
	s := &state.Service{Params: map[string]string{"subnet4": "192.168.200.0/24"}, Secrets: map[string]string{}}
	for k, v := range params {
		s.Params[k] = v
	}
	if err := f.AutoDefaults(testEnv(), s); err != nil {
		t.Fatal(err)
	}
	return f, s
}

func TestFPTNLegacyPortPublishedDirectly(t *testing.T) {
	f, s := fptnTestSvc(t, map[string]string{"legacy_tcp": "2083", "port": "2083"})
	s.Version = "@sha256:6711f36d81fe0e860ca56d66d43a5730d8d4e7a2880a3a2bda8f02c81ba5ca55"
	env := testEnv()
	out := f.compose(env, s)
	for _, want := range []string{
		`image: fptnvpn/fptn-vpn-server@sha256:6711f36d`,
		`ports: ["127.0.0.1:10445:443/tcp", "2083:443/tcp"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в compose:\n%s", want, out)
		}
	}
	direct := false
	for _, n := range f.Needs(env, s) {
		if n.Port == 2083 {
			if n.Redirect || !n.Public {
				t.Fatalf("старый порт должен публиковаться напрямую, а не перенаправляться: %+v", n)
			}
			direct = true
		}
	}
	if !direct {
		t.Fatal("нет потребности в старом порте 2083")
	}
}

func TestFPTNTaggedVersionAndPortsMode(t *testing.T) {
	f, s := fptnTestSvc(t, map[string]string{"port": "2087"})
	s.Version = "0.4.5"
	env := testEnv()
	env.EdgeEnabled = false
	out := f.compose(env, s)
	if !strings.Contains(out, "image: fptnvpn/fptn-vpn-server:0.4.5") || !strings.Contains(out, `ports: ["2087:443/tcp"]`) {
		t.Fatalf("неверный compose:\n%s", out)
	}
}

func TestFPTNEnvKeepsImportedDNS(t *testing.T) {
	f, s := fptnTestSvc(t, map[string]string{"dns_server": "dnsmasq", "dns6_primary": "2001:db8::1", "ads_blocklist_urls": "https://a.example/list.txt"})
	out := f.envFile(testEnv(), s)
	for _, want := range []string{"USING_DNS_SERVER=dnsmasq\n", "DNS_IPV6_PRIMARY=2001:db8::1\n", "DNS_IPV4_PRIMARY=8.8.8.8\n", "ADS_BLOCKLIST_URLS=https://a.example/list.txt\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в fptn.env:\n%s", want, out)
		}
	}
	_, s2 := fptnTestSvc(t, nil)
	if out := f.envFile(testEnv(), s2); !strings.Contains(out, "USING_DNS_SERVER=unbound\n") || strings.Contains(out, "ADS_BLOCKLIST_URLS") {
		t.Errorf("значения по умолчанию изменились:\n%s", out)
	}
}
