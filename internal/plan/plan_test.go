package plan

import (
	"strings"
	"testing"

	"github.com/lineSence/vpnstack/internal/module"
	_ "github.com/lineSence/vpnstack/internal/modules"
	"github.com/lineSence/vpnstack/internal/state"
)

func env(st *state.Stack, r *Result) *module.Env {
	e := &module.Env{Stack: st, EdgePort: 443, EdgeEnabled: true}
	e.Sites = func() []module.CaddySite { return r.Sites }
	e.Routes = func() []module.EdgeRoute { return r.Routes }
	return e
}

func enable(t *testing.T, st *state.Stack, e *module.Env, id string, p map[string]string) {
	m, _ := module.Get(id)
	s := st.Svc(id)
	for k, v := range p {
		s.Params[k] = v
	}
	if err := m.AutoDefaults(e, s); err != nil {
		t.Fatal(err)
	}
	s.Enabled = true
}

func TestPlanRoutesAndOverlap(t *testing.T) {
	st := state.New()
	st.PublicIP = "203.0.113.1"
	var r Result
	e := env(st, &r)
	enable(t, st, e, "xray", map[string]string{"sni": "www.microsoft.com"})
	enable(t, st, e, "tgwp", map[string]string{"domain": "tg.example.com"})
	enable(t, st, e, "fptn", nil)
	r = Build(e, st, nil)
	if !r.NeedCaddy || !r.NeedEdge {
		t.Fatalf("нужны caddy и edge: %+v", r)
	}
	if r.Fatal() {
		t.Fatalf("неожиданные проблемы: %s", r.Errors())
	}
	names := []string{}
	for _, rt := range r.Routes {
		names = append(names, rt.Name)
	}
	if strings.Join(names, ",") != "xray,fptn,caddy" {
		t.Fatalf("порядок маршрутов: %v", names)
	}
	// REALITY под домен из списка FPTN — пересечение.
	st.Svc("xray").Params["sni"] = "yandex.ru"
	r = Build(e, st, nil)
	if !r.Fatal() || !strings.Contains(r.Errors(), "пересекается") {
		t.Fatalf("ожидалось пересечение SNI: %+v", r.Problems)
	}
}

func TestPlanPortDup(t *testing.T) {
	st := state.New()
	st.PublicIP = "203.0.113.1"
	var r Result
	e := env(st, &r)
	enable(t, st, e, "hysteria", nil)
	enable(t, st, e, "awg", map[string]string{"port": "443"})
	r = Build(e, st, nil)
	if !r.Fatal() || !strings.Contains(r.Errors(), "udp/443") {
		t.Fatalf("ожидался конфликт udp/443: %+v", r.Problems)
	}
}

func TestDefaultRouteWithoutCaddy(t *testing.T) {
	st := state.New()
	st.PublicIP = "203.0.113.1"
	var r Result
	e := env(st, &r)
	enable(t, st, e, "xray", nil)
	r = Build(e, st, nil)
	if r.NeedCaddy || len(r.Routes) != 1 || !r.Routes[0].Default {
		t.Fatalf("REALITY должен быть маршрутом по умолчанию: %+v", r.Routes)
	}
}
