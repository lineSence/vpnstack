// Package core — движок оркестратора: установка, настройка, удаление сервисов,
// служебная инфраструктура (Caddy, общий вход, nftables, sysctl), пользователи.
// Используется CLI, TUI и панелью.
package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/modules"
	"github.com/lineSence/vpnstack/internal/netfilter"
	"github.com/lineSence/vpnstack/internal/plan"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Self — установленный путь vpnstack.
const Self = "/usr/local/bin/vpnstack"

// Engine — движок; все изменяющие операции сериализуются.
type Engine struct {
	mu   sync.Mutex
	St   *state.Stack
	Env  *module.Env
	last plan.Result
}

// Open загружает состояние.
func Open() (*Engine, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	e := &Engine{St: st}
	e.Env = &module.Env{
		Stack:     st,
		EdgePort:  443,
		GoBinary:  GoBinary,
		CaddyCert: modules.CaddyCertPaths,
		Self:      Self,
		Host: func(s *state.Service) string {
			if d := s.P("domain"); d != "" {
				return d
			}
			return st.PublicIP
		},
		Sites:  func() []module.CaddySite { return e.last.Sites },
		Routes: func() []module.EdgeRoute { return e.last.Routes },
	}
	e.refresh()
	return e, nil
}

// Lock/Unlock — для длинных операций снаружи (задачи панели).
func (e *Engine) Lock()   { e.mu.Lock() }
func (e *Engine) Unlock() { e.mu.Unlock() }

// TryRun выполняет fn, если движок не занят длинной операцией.
func (e *Engine) TryRun(fn func()) {
	if e.mu.TryLock() {
		defer e.mu.Unlock()
		fn()
	}
}

func (e *Engine) refresh() {
	e.Env.EdgeEnabled = e.St.EdgeMode != "ports"
	e.last = plan.Build(e.Env, e.St, nil)
}

// Plan — проверка текущего состояния с учётом занятых портов.
func (e *Engine) Plan() plan.Result {
	e.Env.EdgeEnabled = e.St.EdgeMode != "ports"
	return plan.Build(e.Env, e.St, sys.Listeners())
}

// Init — первичная настройка (IP, e-mail, режим входа).
func (e *Engine) Init() error {
	if e.St.PublicIP == "" {
		e.St.PublicIP = sys.PublicIPv4()
	}
	if e.St.PublicIP == "" {
		return fmt.Errorf("не удалось определить публичный IPv4 — задайте его: vpnstack set public_ip=1.2.3.4")
	}
	return e.St.Save()
}

func mod(id string) (module.Module, error) {
	m, ok := module.Get(id)
	if !ok {
		return nil, fmt.Errorf("неизвестный сервис %q (список: vpnstack modules)", id)
	}
	return m, nil
}

// Prepare включает сервис, задаёт параметры и автозначения, проверяет план — без установки.
func (e *Engine) Prepare(id string, params map[string]string) (plan.Result, error) {
	m, err := mod(id)
	if err != nil {
		return plan.Result{}, err
	}
	s := e.St.Svc(id)
	for k, v := range params {
		s.Params[k] = strings.TrimSpace(v)
	}
	if err := m.AutoDefaults(e.Env, s); err != nil {
		return plan.Result{}, err
	}
	for _, p := range m.Params() {
		if p.Required && s.P(p.Key) == "" {
			return plan.Result{}, fmt.Errorf("%s: не задан обязательный параметр «%s» (%s)", m.Title(), p.Label, p.Key)
		}
	}
	was := s.Enabled
	s.Enabled = true
	r := e.Plan()
	if !was && r.Fatal() {
		s.Enabled = false
	}
	return r, nil
}

// Install ставит (или переустанавливает) сервис.
func (e *Engine) Install(id string, params map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.Init(); err != nil {
		return err
	}
	m, err := mod(id)
	if err != nil {
		return err
	}
	if s := e.St.Services[id]; s != nil && s.Origin != nil && (s.Origin.State == state.OriginImported || s.Origin.State == state.OriginRolledBack) {
		return fmt.Errorf("%s импортирован из существующей установки — запускайте перенос: vpnstack adopt migrate %s", m.Title(), id)
	}
	r, err := e.Prepare(id, params)
	if err != nil {
		return err
	}
	if r.Fatal() {
		return fmt.Errorf("установка %s невозможна:\n%s", m.Title(), r.Errors())
	}
	for _, p := range r.Problems {
		sys.Logf("[!] %s", p.Msg)
	}
	s := e.St.Svc(id)
	s.Enabled = true
	_ = e.St.Save()
	if err := e.infra(); err != nil {
		return fmt.Errorf("служебные компоненты: %w", err)
	}
	sys.Logf("==> Установка %s", m.Title())
	if err := m.Install(e.Env, s); err != nil {
		s.Error = err.Error()
		_ = e.St.Save()
		return err
	}
	s.Installed, s.Error, s.InstalledAt = true, "", time.Now()
	if um, ok := m.(module.UserManager); ok && len(s.Users) == 0 {
		if _, err := um.AddUser(e.Env, s, "user1", nil); err != nil {
			sys.Logf("[!] не удалось создать первого пользователя: %v", err)
		}
	}
	return e.St.Save()
}

// Reconfigure меняет параметры установленного сервиса и применяет их.
func (e *Engine) Reconfigure(id string, params map[string]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := mod(id)
	if err != nil {
		return err
	}
	s := e.St.Svc(id)
	if !s.Installed {
		return fmt.Errorf("%s не установлен", m.Title())
	}
	old := map[string]string{}
	for k, v := range s.Params {
		old[k] = v
	}
	r, err := e.Prepare(id, params)
	if err == nil && r.Fatal() {
		err = fmt.Errorf("%s", r.Errors())
	}
	if err != nil {
		s.Params = old
		return err
	}
	_ = e.St.Save()
	if err := e.infra(); err != nil {
		return err
	}
	if err := m.Apply(e.Env, s); err != nil {
		s.Error = err.Error()
		_ = e.St.Save()
		return err
	}
	s.Error = ""
	return e.St.Save()
}

// Remove удаляет сервис; purge — вместе с данными, пользователями и настройками.
func (e *Engine) Remove(id string, purge bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := mod(id)
	if err != nil {
		return err
	}
	s := e.St.Svc(id)
	sys.Logf("==> Удаление %s", m.Title())
	if err := m.Remove(e.Env, s, purge); err != nil {
		return err
	}
	s.Enabled, s.Installed = false, false
	if purge {
		delete(e.St.Services, id)
	}
	_ = e.St.Save()
	return e.infra()
}

// Restart перезапускает юниты сервиса.
func (e *Engine) Restart(id string) error {
	m, err := mod(id)
	if err != nil {
		return err
	}
	return sys.Systemctl("restart", m.Units(e.St.Svc(id))...)
}

// Update ставит последнюю версию сервиса.
func (e *Engine) Update(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := mod(id)
	if err != nil {
		return err
	}
	s := e.St.Svc(id)
	if !s.Installed {
		return fmt.Errorf("%s не установлен", m.Title())
	}
	prev := s.Version
	sys.Logf("==> Обновление %s (сейчас %s)", m.Title(), prev)
	err = m.Update(e.Env, s)
	if err == nil && s.Version != prev {
		err = e.probe([]string{id}, 30*time.Second)
	}
	if err != nil {
		rb, ok := m.(module.Rollbacker)
		if !ok || prev == "" || s.Version == prev {
			_ = e.St.Save()
			return err
		}
		sys.Logf("[!] %v", err)
		sys.Logf("==> Возвращаю предыдущую версию %s", prev)
		if rerr := rb.Rollback(e.Env, s, prev); rerr != nil {
			s.Error = rerr.Error()
			_ = e.St.Save()
			return fmt.Errorf("обновление не удалось: %w; откат тоже с ошибкой: %v", err, rerr)
		}
		s.Version, s.Error = prev, ""
		_ = e.St.Save()
		return fmt.Errorf("обновление не удалось, возвращена версия %s: %w", prev, err)
	}
	sys.Logf("    версия: %s", s.Version)
	return e.St.Save()
}

// AddRoute добавляет посторонний сайт/сервис за общим входом 443 (по SNI).
func (e *Engine) AddRoute(r state.Route) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(r.SNI) == 0 || r.Backend == "" {
		return fmt.Errorf("нужны SNI и адрес backend (host:port)")
	}
	if _, _, err := net.SplitHostPort(r.Backend); err != nil {
		return fmt.Errorf("backend %q: нужен host:port", r.Backend)
	}
	for i, x := range e.St.ExtraRoutes {
		for _, a := range x.SNI {
			for _, b := range r.SNI {
				if strings.EqualFold(a, b) {
					return fmt.Errorf("SNI %s уже в маршруте %d (%s)", b, i+1, x.Backend)
				}
			}
		}
	}
	e.St.ExtraRoutes = append(e.St.ExtraRoutes, r)
	return e.infra()
}

// DelRoute удаляет посторонний маршрут по номеру (с 1) или SNI.
func (e *Engine) DelRoute(key string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, x := range e.St.ExtraRoutes {
		hit := fmt.Sprint(i+1) == key
		for _, s := range x.SNI {
			hit = hit || strings.EqualFold(s, key)
		}
		if hit {
			e.St.ExtraRoutes = append(e.St.ExtraRoutes[:i], e.St.ExtraRoutes[i+1:]...)
			return e.infra()
		}
	}
	return fmt.Errorf("маршрут %q не найден", key)
}

// ApplyAll перегенерирует всё (после OTA, смены режима и т. п.).
func (e *Engine) ApplyAll() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.infra(); err != nil {
		return err
	}
	for _, id := range plan.Active(e.St) {
		m, _ := module.Get(id)
		s := e.St.Svc(id)
		if !s.Installed {
			continue
		}
		if err := m.Apply(e.Env, s); err != nil {
			s.Error = err.Error()
			sys.Logf("[!] %s: %v", id, err)
		}
	}
	return e.St.Save()
}

// infra приводит служебные компоненты в соответствие с планом.
func (e *Engine) infra() error {
	e.refresh()
	r := e.last
	for _, c := range []struct {
		id   string
		need bool
	}{{"caddy", r.NeedCaddy}, {"edge", r.NeedEdge}} {
		m, ok := module.Get(c.id)
		if !ok {
			continue
		}
		s := e.St.Svc(c.id)
		switch {
		case c.need && !s.Installed:
			sys.Logf("==> Установка служебного компонента: %s", m.Title())
			s.Enabled = true
			if err := m.AutoDefaults(e.Env, s); err != nil {
				return err
			}
			if err := m.Install(e.Env, s); err != nil {
				s.Error = err.Error()
				return fmt.Errorf("%s: %w", m.Title(), err)
			}
			s.Installed, s.Error, s.InstalledAt = true, "", time.Now()
		case c.need:
			s.Enabled = true
			if err := m.Apply(e.Env, s); err != nil {
				return fmt.Errorf("%s: %w", m.Title(), err)
			}
		case !c.need && s.Installed:
			sys.Logf("==> %s больше не нужен — отключаю", m.Title())
			_ = m.Remove(e.Env, s, false)
			s.Enabled, s.Installed = false, false
		}
	}
	if err := e.firewall(); err != nil {
		return err
	}
	return e.St.Save()
}

func (e *Engine) firewall() error {
	sp := netfilter.Spec{EdgePort: e.Env.EdgePort}
	sysctls := map[string]string{}
	ids := plan.Active(e.St)
	if e.last.NeedCaddy {
		ids = append(ids, "caddy")
	}
	if e.last.NeedEdge {
		ids = append(ids, "edge")
	}
	tcpSeen := map[int]bool{}
	for _, id := range ids {
		m, _ := module.Get(id)
		s := e.St.Svc(id)
		for _, n := range m.Needs(e.Env, s) {
			switch {
			case n.Redirect && n.Proto == "tcp" && n.Port > 0:
				sp.Redirect = append(sp.Redirect, n.Port)
			case n.Proto == "tcp" && !n.Public && n.Port > 0 && !tcpSeen[n.Port]:
				tcpSeen[n.Port] = true
				sp.InternalTCP = append(sp.InternalTCP, n.Port)
			case n.Proto == "udp" && n.Public && n.Port > 0:
				sp.UDP = append(sp.UDP, netfilter.Counter{Service: id, Port: n.Port})
			}
		}
		if np, ok := m.(module.NFTProvider); ok && s.Enabled {
			sp.Extra = append(sp.Extra, np.NFT(e.Env, s))
		}
		if sc, ok := m.(module.Sysctls); ok {
			for k, v := range sc.Sysctls() {
				sysctls[k] = v
			}
		}
	}
	if err := netfilter.ApplySysctl(sysctls); err != nil {
		sys.Logf("[!] sysctl: %v", err)
	}
	return netfilter.Apply(sp)
}

// AddUser добавляет пользователя.
func (e *Engine) AddUser(id, name string, opts map[string]string) (*state.User, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := mod(id)
	if err != nil {
		return nil, err
	}
	um, ok := m.(module.UserManager)
	if !ok {
		return nil, fmt.Errorf("%s не поддерживает пользователей", m.Title())
	}
	name = strings.TrimSpace(name)
	if !validName(name) {
		return nil, fmt.Errorf("имя пользователя: латиница, цифры, - _ . (до 32 символов)")
	}
	s := e.St.Svc(id)
	if s.FindUser(name) != nil {
		return nil, fmt.Errorf("пользователь %s уже есть", name)
	}
	u, err := um.AddUser(e.Env, s, name, opts)
	if err != nil {
		return nil, err
	}
	u.Created = time.Now()
	return u, e.St.Save()
}

func validName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// DelUser удаляет пользователя.
func (e *Engine) DelUser(id, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, err := mod(id)
	if err != nil {
		return err
	}
	um, ok := m.(module.UserManager)
	if !ok {
		return fmt.Errorf("%s не поддерживает пользователей", m.Title())
	}
	if err := um.DelUser(e.Env, e.St.Svc(id), name); err != nil {
		return err
	}
	return e.St.Save()
}

// Artifacts — ссылки/файлы пользователя (или общие ссылки сервиса, если name пусто).
func (e *Engine) Artifacts(id, name string) ([]module.Artifact, error) {
	m, err := mod(id)
	if err != nil {
		return nil, err
	}
	s := e.St.Svc(id)
	if name == "" {
		if l, ok := m.(module.Linker); ok {
			return l.Links(e.Env, s)
		}
		return nil, nil
	}
	um, ok := m.(module.UserManager)
	if !ok {
		return nil, fmt.Errorf("%s не поддерживает пользователей", m.Title())
	}
	u := s.FindUser(name)
	if u == nil {
		return nil, fmt.Errorf("нет пользователя %s", name)
	}
	return um.Artifacts(e.Env, s, u)
}

// SvcInfo — сводка по сервису.
type SvcInfo struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Core        bool              `json:"core"`
	External    bool              `json:"external"`
	Enabled     bool              `json:"enabled"`
	Installed   bool              `json:"installed"`
	Version     string            `json:"version"`
	Error       string            `json:"error,omitempty"`
	Status      module.Status     `json:"status"`
	Params      []module.Param    `json:"params"`
	Values      map[string]string `json:"values"`
	Users       []UserInfo        `json:"users,omitempty"`
	HasUsers    bool              `json:"has_users"`
	HasLinks    bool              `json:"has_links"`
	Configs     []string          `json:"configs,omitempty"`
}

// UserInfo — пользователь без секретов.
type UserInfo struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Note    string    `json:"note,omitempty"`
}

// Services — сводка по всем модулям.
func (e *Engine) Services() []SvcInfo {
	var out []SvcInfo
	for _, m := range module.All() {
		s := e.St.Svc(m.ID())
		if m.Core() && !s.Installed {
			continue
		}
		in := SvcInfo{ID: m.ID(), Title: m.Title(), Description: m.Description(), Core: m.Core(),
			Enabled: s.Enabled, Installed: s.Installed, Version: s.Version, Error: s.Error,
			Status: m.Status(e.Env, s), Params: m.Params(), Values: map[string]string{}}
		_, in.External = m.(*module.External)
		for k, v := range s.Params {
			in.Values[k] = v
		}
		_, in.HasUsers = m.(module.UserManager)
		if x, ok := m.(*module.External); ok {
			in.HasUsers = x.M.Users
		}
		_, in.HasLinks = m.(module.Linker)
		if c, ok := m.(module.Configurer); ok {
			in.Configs = c.ConfigFiles(s)
		}
		for _, u := range s.Users {
			in.Users = append(in.Users, UserInfo{Name: u.Name, Created: u.Created, Note: u.Note})
		}
		out = append(out, in)
	}
	return out
}

// Tick — периодические действия модулей (сертификаты и т. п.).
func (e *Engine) Tick() {
	e.TryRun(e.tick)
}

func (e *Engine) tick() {
	changed := false
	for _, id := range plan.Active(e.St) {
		m, _ := module.Get(id)
		if t, ok := m.(module.Ticker); ok {
			t.Tick(e.Env, e.St.Svc(id))
			changed = true
		}
	}
	if changed {
		_ = e.St.Save()
	}
}

// LatestVersions — последние версии установленных сервисов.
func (e *Engine) LatestVersions() map[string]string {
	out := map[string]string{}
	for _, m := range module.All() {
		s := e.St.Svc(m.ID())
		if !s.Installed {
			continue
		}
		if v, err := m.Latest(e.Env); err == nil && v != "" {
			out[m.ID()] = v
		}
	}
	return out
}

// GoBinary возвращает Go для сборки из исходников (ставит последний стабильный при необходимости).
func GoBinary() (string, error) {
	const dir = "/opt/vpnstack/go"
	if p := filepath.Join(dir, "bin", "go"); sys.Exists(p) {
		return p, nil
	}
	resp, err := http.Get("https://go.dev/dl/?mode=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var rel []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
		Files   []struct {
			Filename, OS, Arch, Kind, SHA256 string
		} `json:"files"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &rel); err != nil {
		return "", err
	}
	for _, r := range rel {
		if !r.Stable {
			continue
		}
		for _, f := range r.Files {
			if f.OS == "linux" && f.Arch == sysArch() && f.Kind == "archive" {
				tmp := filepath.Join("/tmp", f.Filename)
				sys.Logf("Скачиваю %s", r.Version)
				if err := sys.DownloadVerified("https://go.dev/dl/"+f.Filename, tmp, f.SHA256); err != nil {
					return "", err
				}
				_ = os.RemoveAll(dir)
				if _, err := sys.Run("tar", "-C", "/opt/vpnstack", "-xzf", tmp); err != nil {
					return "", err
				}
				os.Remove(tmp)
				return filepath.Join(dir, "bin", "go"), nil
			}
		}
	}
	return "", fmt.Errorf("не найден архив Go для linux/%s", sysArch())
}

// IDs — идентификаторы сервисов (не служебных), отсортированные.
func IDs() []string {
	var ids []string
	for _, m := range module.All() {
		if !m.Core() {
			ids = append(ids, m.ID())
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return false })
	return ids
}

// Preview — проверка плана с новыми параметрами без сохранения.
func (e *Engine) Preview(id string, params map[string]string) (plan.Result, error) {
	if !e.mu.TryLock() {
		return plan.Result{}, fmt.Errorf("идёт другая операция — повторите позже")
	}
	defer e.mu.Unlock()
	_, existed := e.St.Services[id]
	s := e.St.Svc(id)
	saved := *s
	saved.Params = clone(s.Params)
	saved.Secrets = clone(s.Secrets)
	defer func() {
		if existed {
			*s = saved
		} else {
			delete(e.St.Services, id)
		}
		e.refresh()
	}()
	return e.Prepare(id, params)
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
