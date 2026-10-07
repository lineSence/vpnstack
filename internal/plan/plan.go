// Package plan проверяет совместимость сервисов: порты, конфликты с посторонними
// программами, пересечения SNI на общем входе, DNS доменов.
package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lineSence/vpnstack/internal/edge"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Problem — найденная проблема.
type Problem struct {
	Service string `json:"service"`
	Kind    string `json:"kind"` // port_dup | port_busy | sni_overlap | dns | param
	Msg     string `json:"msg"`
	Proto   string `json:"proto,omitempty"`
	Port    int    `json:"port,omitempty"`
	Unit    string `json:"unit,omitempty"` // юнит, который можно остановить
	PID     int    `json:"pid,omitempty"`
	Fatal   bool   `json:"fatal"`
}

// Result — итог проверки.
type Result struct {
	Problems  []Problem          `json:"problems"`
	Routes    []module.EdgeRoute `json:"routes"`
	Sites     []module.CaddySite `json:"sites"`
	NeedCaddy bool               `json:"need_caddy"`
	NeedEdge  bool               `json:"need_edge"`
	Active    []string           `json:"active"`
}

// Fatal — есть ли блокирующие проблемы.
func (r *Result) Fatal() bool {
	for _, p := range r.Problems {
		if p.Fatal {
			return true
		}
	}
	return false
}

// Errors — текст блокирующих проблем.
func (r *Result) Errors() string {
	var s []string
	for _, p := range r.Problems {
		if p.Fatal {
			s = append(s, "• "+p.Msg)
		}
	}
	return strings.Join(s, "\n")
}

// Active — сервисы, которые должны работать (включены), без служебных.
func Active(st *state.Stack) []string {
	var ids []string
	for _, id := range st.EnabledIDs() {
		if m, ok := module.Get(id); ok && !m.Core() {
			ids = append(ids, id)
		}
	}
	return ids
}

// Build строит план для включённых сервисов. listeners == nil — не проверять занятость.
func Build(env *module.Env, st *state.Stack, listeners []sys.Listener) Result {
	var r Result
	r.Active = Active(st)
	for _, id := range r.Active {
		m, _ := module.Get(id)
		if cc, ok := m.(module.CaddyConsumer); ok {
			r.Sites = append(r.Sites, cc.CaddySites(env, st.Svc(id))...)
		}
	}
	r.NeedCaddy = len(r.Sites) > 0
	type owned struct {
		id   string
		need module.Need
	}
	var needs []owned
	claimed := map[string]bool{} // SNI, занятые не-Caddy маршрутами
	for _, id := range r.Active {
		m, _ := module.Get(id)
		for _, n := range m.Needs(env, st.Svc(id)) {
			needs = append(needs, owned{id, n})
			if n.Edge != nil {
				rt := *n.Edge
				rt.Name = id
				r.Routes = append(r.Routes, rt)
				for _, s := range rt.SNI {
					claimed[s] = true
				}
			}
		}
	}
	// Посторонние маршруты (сайты других веб-серверов за общим входом).
	if env.EdgeEnabled {
		for i, x := range st.ExtraRoutes {
			r.Routes = append(r.Routes, module.EdgeRoute{Name: fmt.Sprintf("extra%d", i+1), SNI: x.SNI,
				Backend: x.Backend, ProxyProtocol: x.ProxyProtocol, Priority: 40})
			for _, s := range x.SNI {
				claimed[s] = true
			}
		}
	}
	r.NeedEdge = env.EdgeEnabled && (len(r.Routes) > 0 || r.NeedCaddy)
	for _, core := range []struct {
		id   string
		need bool
	}{{"caddy", r.NeedCaddy}, {"edge", r.NeedEdge}} {
		if !core.need {
			continue
		}
		m, ok := module.Get(core.id)
		if !ok {
			continue
		}
		for _, n := range m.Needs(env, st.Svc(core.id)) {
			needs = append(needs, owned{core.id, n})
			if n.Edge != nil {
				rt := *n.Edge
				rt.Name = core.id
				var sni []string
				for _, s := range rt.SNI {
					if !claimed[s] {
						sni = append(sni, s)
					}
				}
				rt.SNI = sni
				r.Routes = append(r.Routes, rt)
			}
		}
	}
	// Дубли портов между сервисами стека.
	seen := map[string]string{}
	for _, o := range needs {
		if o.need.Port == 0 {
			continue
		}
		k := fmt.Sprintf("%s/%d", o.need.Proto, o.need.Port)
		if prev, ok := seen[k]; ok && prev != o.id {
			r.Problems = append(r.Problems, Problem{Service: o.id, Kind: "port_dup", Proto: o.need.Proto, Port: o.need.Port, Fatal: true,
				Msg: fmt.Sprintf("порт %s нужен и «%s», и «%s» — измените порт одного из них", k, prev, o.id)})
			continue
		}
		seen[k] = o.id
	}
	// Занятость портов посторонними программами.
	if listeners != nil {
		for _, o := range needs {
			for _, l := range listeners {
				if l.Proto != o.need.Proto || l.Port != o.need.Port {
					continue
				}
				unit := sys.UnitOfPID(l.PID)
				if ownedBy(st, o.id, unit, l.Process) {
					continue
				}
				r.Problems = append(r.Problems, Problem{Service: o.id, Kind: "port_busy", Proto: l.Proto, Port: l.Port, Unit: unit, PID: l.PID, Fatal: true,
					Msg: fmt.Sprintf("%s/%d (%s) занят: %s (pid %d, %s)", l.Proto, l.Port, o.need.Purpose, l.Process, l.PID, orDash(unit))})
				break
			}
		}
	}
	// Пересечения SNI (кроме маршрута Caddy по умолчанию — он получает остаток).
	for i := 0; i < len(r.Routes); i++ {
		for j := i + 1; j < len(r.Routes); j++ {
			a, b := r.Routes[i], r.Routes[j]
			if a.Name == b.Name || a.Name == "caddy" || b.Name == "caddy" {
				continue
			}
			for _, x := range a.SNI {
				for _, y := range b.SNI {
					if edge.MatchSNI(x, y) || edge.MatchSNI(y, x) {
						r.Problems = append(r.Problems, Problem{Service: b.Name, Kind: "sni_overlap", Fatal: true,
							Msg: fmt.Sprintf("SNI «%s» (%s) пересекается с «%s» (%s) — общий вход не сможет их различить", x, a.Name, y, b.Name)})
					}
				}
			}
		}
	}
	// DNS доменов, для которых нужен сертификат.
	for _, s := range r.Sites {
		if ok, ips := sys.DNSPointsHere(s.Host, st.PublicIP); !ok {
			r.Problems = append(r.Problems, Problem{Kind: "dns", Msg: fmt.Sprintf("A-запись %s указывает на %v, а не на %s — сертификат не выпустится", s.Host, ips, st.PublicIP)})
		}
	}
	sort.SliceStable(r.Routes, func(i, j int) bool { return r.Routes[i].Priority > r.Routes[j].Priority })
	// Без Caddy неизвестные SNI получает REALITY (он перешлёт их на настоящий сайт-цель).
	hasDef := false
	for _, rt := range r.Routes {
		hasDef = hasDef || rt.Default
	}
	if !hasDef {
		for i := range r.Routes {
			if r.Routes[i].Name == "xray" {
				r.Routes[i].Default = true
			}
		}
	}
	return r
}

func orDash(s string) string {
	if s == "" {
		return "не systemd"
	}
	return s
}

// ownedBy — порт занят самим сервисом стека.
func ownedBy(st *state.Stack, id, unit, proc string) bool {
	if unit == "" && proc == "" {
		return false
	}
	if strings.HasPrefix(unit, "vpnstack") {
		return true
	}
	if m, ok := module.Get(id); ok {
		for _, u := range m.Units(st.Svc(id)) {
			if u == unit {
				return true
			}
		}
	}
	if id == "fptn" && (proc == "docker-proxy" || unit == "docker.service") {
		return true
	}
	return false
}

// FreePort подбирает свободный порт в диапазоне, не занятый стеком и системой.
func FreePort(proto string, lo, hi int, used map[int]bool, listeners []sys.Listener) int {
	for i := 0; i < 2000; i++ {
		p := lo + int(sys.RandUint(uint64(hi-lo+1)))
		if used[p] {
			continue
		}
		busy := false
		for _, l := range listeners {
			if l.Proto == proto && l.Port == p {
				busy = true
				break
			}
		}
		if !busy {
			return p
		}
	}
	return 0
}
