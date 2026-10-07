package netfilter

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	out := Render(Spec{InternalTCP: []int{10443, 7443}, UDP: []Counter{{"hysteria", 443}}, Extra: []string{"chain x {\n\ttype nat hook postrouting priority srcnat;\n}"}})
	for _, w := range []string{"delete table inet vpnstack", `iifname != "lo" tcp dport { 7443, 10443 } drop`, "udp dport 443 counter name hysteria_rx", "udp sport 443 counter name hysteria_tx", "\tchain x {"} {
		if !strings.Contains(out, w) {
			t.Errorf("нет %q:\n%s", w, out)
		}
	}
}

func TestRedirect(t *testing.T) {
	out := Render(Spec{Redirect: []int{8443, 2053}, EdgePort: 443})
	if !strings.Contains(out, "fib daddr type local tcp dport { 2053, 8443 } redirect to :443") {
		t.Fatal(out)
	}
}
