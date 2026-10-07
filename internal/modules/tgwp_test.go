package modules

import (
	"os"
	"strings"
	"testing"

	"github.com/lineSence/vpnstack/internal/state"
)

// Проверка патча на штатном install.sh (путь задаётся TPROXY_INSTALL_SH).
func TestPatchInstaller(t *testing.T) {
	p := os.Getenv("TPROXY_INSTALL_SH")
	if p == "" {
		t.Skip("TPROXY_INSTALL_SH не задан")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out, err := patchInstaller(string(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"caddy_version=", "systemctl restart caddy.service", "caddy validate", "Caddyfile.tproxy", "caddy.service.d/tproxy.conf"} {
		if strings.Contains(out, bad) {
			t.Errorf("осталось %q", bad)
		}
	}
	for _, good := range []string{"install-mtproxy.sh", "systemctl enable --now tproxy-server.service", "useradd --system --home /var/lib/caddy"} {
		if !strings.Contains(out, good) {
			t.Errorf("пропало %q", good)
		}
	}
	os.WriteFile("/tmp/install-patched.sh", []byte(out), 0o755)
}

func TestTGWPAdoptedNeeds(t *testing.T) {
	tg := &TGWP{}
	for _, adopted := range []bool{false, true} {
		s := &state.Service{Params: map[string]string{}}
		if adopted {
			s.Params["adopted_inplace"] = "true"
		}
		ports := map[int]bool{}
		for _, n := range tg.Needs(testEnv(), s) {
			ports[n.Port] = true
		}
		if !ports[8080] || !ports[8081] {
			t.Fatal("web/readiness ports must remain checked")
		}
		if ports[8888] == adopted || ports[2398] == adopted {
			t.Fatalf("adopted=%v: unexpected needs %v", adopted, ports)
		}
	}
}
