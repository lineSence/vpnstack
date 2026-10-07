package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// ExternalDir — каталог сторонних модулей: <dir>/<id>/module.json + скрипты-хуки.
var ExternalDir = "/etc/vpnstack/modules.d"

// Manifest — описание стороннего модуля (см. docs/MODULES.md).
type Manifest struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Order       int     `json:"order"`
	Params      []Param `json:"params"`
	// Defaults — значения по умолчанию; "$random_port", "$hex16", "$password" генерируются.
	Defaults map[string]string `json:"defaults"`
	Needs    []ManifestNeed    `json:"needs"`
	Units    []string          `json:"units"`
	// CaddySite — если задан: домен берётся из параметра host_param, блок — как есть
	// (пусто — сайт-прикрытие). {param:x} в блоке заменяется значением параметра.
	CaddySite *struct {
		HostParam string `json:"host_param"`
		Block     string `json:"block"`
	} `json:"caddy_site,omitempty"`
	Users   bool              `json:"users"`
	Hooks   map[string]string `json:"hooks"` // install apply remove status latest update add_user del_user artifacts traffic links
	Timeout int               `json:"timeout"`
}

// ManifestNeed — порт стороннего модуля.
type ManifestNeed struct {
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	PortParam string `json:"port_param"` // порт из параметра
	Public    bool   `json:"public"`
	Purpose   string `json:"purpose"`
	// Edge — маршрут общего входа: SNI из параметров sni_params, backend 127.0.0.1:<port>.
	Edge *struct {
		SNIParams     []string `json:"sni_params"`
		ProxyProtocol bool     `json:"proxy_protocol"`
		Priority      int      `json:"priority"`
	} `json:"edge,omitempty"`
	// EdgeOnly / PortsOnly — потребность только в одном из режимов входа.
	EdgeOnly  bool `json:"edge_only"`
	PortsOnly bool `json:"ports_only"`
}

// External — модуль на основе манифеста и хуков.
type External struct {
	M   Manifest
	Dir string
}

// LoadExternal регистрирует сторонние модули из ExternalDir.
func LoadExternal() []error {
	var errs []error
	dirs, _ := filepath.Glob(filepath.Join(ExternalDir, "*", "module.json"))
	for _, f := range dirs {
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
			continue
		}
		if m.ID == "" || m.Hooks["install"] == "" {
			errs = append(errs, fmt.Errorf("%s: нужны id и hooks.install", f))
			continue
		}
		if _, dup := Get(m.ID); dup {
			errs = append(errs, fmt.Errorf("%s: id %q уже занят встроенным модулем", f, m.ID))
			continue
		}
		if m.Order == 0 {
			m.Order = 800
		}
		Register(&External{M: m, Dir: filepath.Dir(f)})
	}
	return errs
}

// hookIn — данные, передаваемые хуку на stdin.
type hookIn struct {
	Hook    string            `json:"hook"`
	Service *state.Service    `json:"service"`
	Stack   map[string]any    `json:"stack"`
	User    *state.User       `json:"user,omitempty"`
	Name    string            `json:"name,omitempty"`
	Opts    map[string]string `json:"opts,omitempty"`
}

// hookOut — ответ хука (stdout, JSON; всё необязательно).
type hookOut struct {
	Params    map[string]string  `json:"params"`
	Secrets   map[string]string  `json:"secrets"`
	Version   string             `json:"version"`
	State     string             `json:"state"`
	Detail    string             `json:"detail"`
	User      map[string]string  `json:"user"` // данные нового пользователя
	Artifacts []Artifact         `json:"artifacts"`
	Traffic   map[string]Traffic `json:"traffic"`
}

func (x *External) run(env *Env, s *state.Service, hook string, in hookIn) (*hookOut, error) {
	script := x.M.Hooks[hook]
	if script == "" {
		return &hookOut{}, nil
	}
	if !filepath.IsAbs(script) {
		script = filepath.Join(x.Dir, script)
	}
	in.Hook, in.Service = hook, s
	in.Stack = map[string]any{"public_ip": env.Stack.PublicIP, "email": env.Stack.Email,
		"edge_enabled": env.EdgeEnabled, "edge_port": env.EdgePort, "site_dir": "/var/lib/vpnstack/site"}
	b, _ := json.Marshal(in)
	to := time.Duration(x.M.Timeout) * time.Second
	if to == 0 {
		to = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	cmd := exec.CommandContext(ctx, script)
	cmd.Dir = x.Dir
	cmd.Stdin = bytes.NewReader(b)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = sys.Log // журнал задачи
	cmd.Env = append(os.Environ(), "VPNSTACK_HOOK="+hook, "VPNSTACK_SERVICE="+x.M.ID)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("хук %s модуля %s: %w", hook, x.M.ID, err)
	}
	var o hookOut
	if bytes.TrimSpace(out.Bytes()) != nil && len(bytes.TrimSpace(out.Bytes())) > 0 {
		if err := json.Unmarshal(out.Bytes(), &o); err != nil {
			return nil, fmt.Errorf("хук %s модуля %s вернул не JSON: %w", hook, x.M.ID, err)
		}
	}
	for k, v := range o.Params {
		s.Params[k] = v
	}
	if len(o.Secrets) > 0 && s.Secrets == nil {
		s.Secrets = map[string]string{}
	}
	for k, v := range o.Secrets {
		s.Secrets[k] = v
	}
	if o.Version != "" {
		s.Version = o.Version
	}
	return &o, nil
}

func (x *External) ID() string                    { return x.M.ID }
func (x *External) Title() string                 { return x.M.Title }
func (x *External) Description() string           { return x.M.Description }
func (x *External) Params() []Param               { return x.M.Params }
func (x *External) Core() bool                    { return false }
func (x *External) Order() int                    { return x.M.Order }
func (x *External) Units(*state.Service) []string { return x.M.Units }

func (x *External) AutoDefaults(env *Env, s *state.Service) error {
	for k, v := range x.M.Defaults {
		switch v {
		case "$random_port":
			v = strconv.Itoa(20000 + int(sys.RandUint(30000)))
		case "$hex16":
			v = sys.RandHex(16)
		case "$password":
			v = sys.RandHex(12)
		}
		s.Default(k, v)
	}
	return nil
}

func (x *External) Needs(env *Env, s *state.Service) []Need {
	var out []Need
	for _, n := range x.M.Needs {
		if n.EdgeOnly && !env.EdgeEnabled || n.PortsOnly && env.EdgeEnabled {
			continue
		}
		port := n.Port
		if n.PortParam != "" {
			port, _ = strconv.Atoi(s.P(n.PortParam))
		}
		nd := Need{Proto: n.Proto, Port: port, Public: n.Public, Purpose: n.Purpose, Param: n.PortParam}
		if n.Edge != nil && env.EdgeEnabled {
			var sni []string
			for _, p := range n.Edge.SNIParams {
				if v := s.P(p); v != "" {
					sni = append(sni, v)
				}
			}
			nd.Edge = &EdgeRoute{SNI: sni, Backend: fmt.Sprintf("127.0.0.1:%d", port), ProxyProtocol: n.Edge.ProxyProtocol, Priority: n.Edge.Priority}
		}
		out = append(out, nd)
	}
	return out
}

// CaddySites — сайт стороннего модуля.
func (x *External) CaddySites(env *Env, s *state.Service) []CaddySite {
	if x.M.CaddySite == nil || s.P(x.M.CaddySite.HostParam) == "" {
		return nil
	}
	blk := x.M.CaddySite.Block
	for k, v := range s.Params {
		blk = replaceAll(blk, "{param:"+k+"}", v)
	}
	return []CaddySite{{Host: s.P(x.M.CaddySite.HostParam), Block: blk, Order: x.M.Order}}
}

func replaceAll(s, old, new string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new)))
}

func (x *External) Install(env *Env, s *state.Service) error {
	_, err := x.run(env, s, "install", hookIn{})
	if err == nil && len(x.M.Units) > 0 {
		for _, u := range x.M.Units {
			_ = sys.AttachToSlice(u, x.M.ID)
		}
		_ = sys.EnsureSlice(x.M.ID, x.M.Title)
		_ = sys.Systemctl("daemon-reload")
		_ = sys.Systemctl("restart", x.M.Units...)
	}
	return err
}

func (x *External) Apply(env *Env, s *state.Service) error {
	_, err := x.run(env, s, "apply", hookIn{})
	return err
}

func (x *External) Remove(env *Env, s *state.Service, purge bool) error {
	_, err := x.run(env, s, "remove", hookIn{Opts: map[string]string{"purge": strconv.FormatBool(purge)}})
	sys.RemoveUnit(sys.SliceName(x.M.ID))
	return err
}

func (x *External) Status(env *Env, s *state.Service) Status {
	st := Status{Units: map[string]string{}, Version: s.Version}
	if !s.Installed {
		st.State = "not_installed"
		return st
	}
	if x.M.Hooks["status"] != "" {
		if o, err := x.run(env, s, "status", hookIn{}); err == nil && o.State != "" {
			st.State, st.Detail = o.State, o.Detail
			return st
		}
	}
	st.State = "running"
	for _, u := range x.M.Units {
		v := sys.UnitState(u)
		st.Units[u] = v
		if v != "active" {
			st.State = "failed"
		}
	}
	return st
}

func (x *External) Latest(env *Env) (string, error) {
	if x.M.Hooks["latest"] == "" {
		return "", nil
	}
	tmp := &state.Service{Params: map[string]string{}}
	o, err := x.run(env, tmp, "latest", hookIn{})
	if err != nil {
		return "", err
	}
	return o.Version, nil
}

func (x *External) Update(env *Env, s *state.Service) error {
	hook := "update"
	if x.M.Hooks[hook] == "" {
		hook = "install"
	}
	_, err := x.run(env, s, hook, hookIn{})
	return err
}

// externalUsers — сторонний модуль с пользователями.
func (x *External) AddUser(env *Env, s *state.Service, name string, opts map[string]string) (*state.User, error) {
	if !x.M.Users {
		return nil, fmt.Errorf("модуль %s не поддерживает пользователей", x.M.ID)
	}
	u := &state.User{Name: name, Data: map[string]string{}}
	s.Users = append(s.Users, u)
	o, err := x.run(env, s, "add_user", hookIn{Name: name, User: u, Opts: opts})
	if err != nil {
		s.RemoveUser(name)
		return nil, err
	}
	for k, v := range o.User {
		u.Data[k] = v
	}
	return u, nil
}

func (x *External) DelUser(env *Env, s *state.Service, name string) error {
	u := s.FindUser(name)
	if u == nil {
		return fmt.Errorf("нет пользователя %s", name)
	}
	s.RemoveUser(name)
	if _, err := x.run(env, s, "del_user", hookIn{Name: name, User: u}); err != nil {
		s.Users = append(s.Users, u)
		return err
	}
	return nil
}

func (x *External) Artifacts(env *Env, s *state.Service, u *state.User) ([]Artifact, error) {
	o, err := x.run(env, s, "artifacts", hookIn{Name: u.Name, User: u})
	if err != nil {
		return nil, err
	}
	return o.Artifacts, nil
}

func (x *External) UserTraffic(env *Env, s *state.Service) (map[string]Traffic, error) {
	if x.M.Hooks["traffic"] == "" {
		return nil, nil
	}
	o, err := x.run(env, s, "traffic", hookIn{})
	if err != nil {
		return nil, err
	}
	return o.Traffic, nil
}
