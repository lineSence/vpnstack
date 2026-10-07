package plan

import (
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
	"testing"
)

func TestTGWPAdoptionWithSearxng(t *testing.T) {
	st := state.New()
	var r Result
	e := env(st, &r)
	enable(t, st, e, "hysteria", map[string]string{"domain": "uwu.example.com"})
	enable(t, st, e, "tgwp", map[string]string{"domain": "tg.example.com", "adopted_inplace": "true"})
	listeners := []sys.Listener{{Proto: "tcp", Port: 8888, Addr: "127.0.0.1", Process: "docker-proxy", PID: -1}}
	r = Build(e, st, listeners)
	if r.Fatal() {
		t.Fatalf("SearXNG must not block in-place migration: %s", r.Errors())
	}
	delete(st.Svc("tgwp").Params, "adopted_inplace")
	r = Build(e, st, listeners)
	if !r.Fatal() {
		t.Fatal("new installation must still reject occupied 8888")
	}
	for _, p := range r.Problems {
		if p.Kind == "port_busy" && p.Port == 8888 {
			return
		}
	}
	t.Fatalf("expected busy 8888: %+v", r.Problems)
}
