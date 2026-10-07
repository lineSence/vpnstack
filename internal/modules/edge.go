package modules

import (
	"encoding/json"
	"fmt"

	"github.com/lineSence/vpnstack/internal/edge"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Edge — общий вход TCP 443: маршрутизирует соединения по SNI к сервисам.
// Это сам vpnstack в режиме `vpnstack edge`, отдельный юнит.
type Edge struct{ base }

// EdgeStatsAddr — адрес счётчиков общего входа.
const EdgeStatsAddr = "127.0.0.1:8898"

func init() {
	module.Register(&Edge{base{id: "edge", title: "Общий вход 443", order: 5,
		desc:  "Маршрутизация TCP 443 по SNI между Caddy, Xray, telemt и FPTN",
		units: []string{"vpnstack-edge.service"}}})
}

func (e *Edge) Core() bool                                           { return true }
func (e *Edge) Params() []module.Param                               { return nil }
func (e *Edge) AutoDefaults(env *module.Env, s *state.Service) error { return nil }

func (e *Edge) Needs(env *module.Env, s *state.Service) []module.Need {
	return []module.Need{{Proto: "tcp", Port: env.EdgePort, Public: true, Purpose: "общий вход по SNI"},
		{Proto: "tcp", Port: 8898, Purpose: "счётчики общего входа"}}
}

func (e *Edge) Latest(env *module.Env) (string, error) { return "", nil }

func (e *Edge) config(env *module.Env) edge.Config {
	cfg := edge.Config{Listen: fmt.Sprintf(":%d", env.EdgePort), StatsListen: EdgeStatsAddr}
	if env.Routes != nil {
		for _, r := range env.Routes() {
			cfg.Routes = append(cfg.Routes, edge.Route{Name: r.Name, SNI: r.SNI, Backend: r.Backend,
				ProxyProtocol: r.ProxyProtocol, Default: r.Default, Priority: r.Priority})
		}
	}
	return cfg
}

func (e *Edge) write(env *module.Env) error {
	b, _ := json.MarshalIndent(e.config(env), "", "  ")
	return sys.WriteFileAtomic(edge.ConfigPath, b, 0o644)
}

func (e *Edge) Install(env *module.Env, s *state.Service) error {
	if err := e.write(env); err != nil {
		return err
	}
	unit := serviceUnit(e.id, "общий вход TCP 443 (SNI)", env.Self+" edge", `ExecReload=/bin/kill -HUP $MAINPID
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
`)
	if err := installUnit(e.id, e.title, e.units[0], unit); err != nil {
		return err
	}
	s.Version = "builtin"
	return waitActive(e.units[0], 10e9)
}

func (e *Edge) Apply(env *module.Env, s *state.Service) error {
	if err := e.write(env); err != nil {
		return err
	}
	if sys.Active(e.units[0]) {
		return sys.Systemctl("reload", e.units[0])
	}
	return sys.Systemctl("restart", e.units[0])
}

func (e *Edge) Remove(env *module.Env, s *state.Service, purge bool) error {
	removeUnits(e.id, e.units...)
	return nil
}

func (e *Edge) Status(env *module.Env, s *state.Service) module.Status {
	return unitsStatus(s, e.units)
}

func (e *Edge) Update(env *module.Env, s *state.Service) error {
	// Обновляется вместе с vpnstack (OTA) — достаточно перезапуска.
	return sys.Systemctl("restart", e.units[0])
}

func (e *Edge) ConfigFiles(*state.Service) []string { return []string{edge.ConfigPath} }
