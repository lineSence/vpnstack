package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/adopt"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/modules"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// AdoptDir — резервные копии старых установок.
var AdoptDir = "/var/lib/vpnstack/adopt"

// AdoptScan ищет установки без vpnstack и отмечает их статус относительно состояния.
func (e *Engine) AdoptScan() *adopt.Report {
	r := adopt.Scan()
	for _, f := range r.Found {
		s := e.St.Services[f.ID]
		switch {
		case s == nil:
			f.Status = "new"
		case s.Origin != nil:
			f.Status = s.Origin.State
		case s.Installed:
			f.Status = "conflict"
		default:
			f.Status = "new"
		}
	}
	return r
}

// Adopted — сервисы, перенятые (или перенимаемые) из старых установок.
func (e *Engine) Adopted() map[string]*state.Origin {
	out := map[string]*state.Origin{}
	for id, s := range e.St.Services {
		if s.Origin != nil {
			out[id] = s.Origin
		}
	}
	return out
}

func pick(r *adopt.Report, ids []string) ([]*adopt.Found, error) {
	all := len(ids) == 0 || (len(ids) == 1 && ids[0] == "all")
	byID := map[string][]*adopt.Found{}
	for _, f := range r.Found {
		byID[f.ID] = append(byID[f.ID], f)
	}
	var want []string
	if all {
		for id := range byID {
			want = append(want, id)
		}
		sort.Strings(want)
	} else {
		want = ids
	}
	var out []*adopt.Found
	for _, id := range want {
		fs := byID[id]
		switch {
		case len(fs) == 0:
			return nil, fmt.Errorf("установка «%s» не найдена (vpnstack adopt scan)", id)
		case len(fs) > 1:
			var src []string
			for _, f := range fs {
				src = append(src, f.Origin.Source)
			}
			return nil, fmt.Errorf("найдено несколько установок «%s»: %s — vpnstack переносит одну; остановите лишние", id, strings.Join(src, "; "))
		}
		out = append(out, fs[0])
	}
	return out, nil
}

// AdoptImport считывает найденные установки в состояние vpnstack (старые продолжают работать).
func (e *Engine) AdoptImport(ids []string, force bool) ([]string, error) {
	e.Lock()
	defer e.Unlock()
	r := e.AdoptScan()
	found, err := pick(r, ids)
	if err != nil {
		return nil, err
	}
	var msgs []string
	for _, f := range found {
		if err := e.importOne(f, force); err != nil {
			if len(ids) == 0 || ids[0] == "all" {
				msgs = append(msgs, fmt.Sprintf("[!] %s: %v", f.Title, err))
				continue
			}
			return msgs, err
		}
		msgs = append(msgs, fmt.Sprintf("%s: импортирован (%d польз.)", f.Title, len(f.Users)))
	}
	return msgs, e.St.Save()
}

func (e *Engine) importOne(f *adopt.Found, force bool) error {
	m, err := mod(f.ID)
	if err != nil {
		return err
	}
	if len(f.Blocking) > 0 {
		return fmt.Errorf("перенос невозможен:\n  • %s", strings.Join(f.Blocking, "\n  • "))
	}
	if len(f.Risky) > 0 && !force {
		return fmt.Errorf("нужно подтверждение (--force):\n  • %s", strings.Join(f.Risky, "\n  • "))
	}
	if s := e.St.Services[f.ID]; s != nil {
		switch {
		case s.Origin != nil && s.Origin.State == state.OriginMigrated:
			return fmt.Errorf("уже перенесён; для повторного переноса сначала: vpnstack adopt rollback %s", f.ID)
		case s.Origin == nil && s.Installed:
			return fmt.Errorf("%s уже установлен vpnstack — два экземпляра одного сервиса не поддерживаются", m.Title())
		}
	}
	s := &state.Service{Params: map[string]string{}, Secrets: map[string]string{}}
	for k, v := range f.Params {
		if k == "_version" {
			s.Version = v
			continue
		}
		s.Params[k] = v
	}
	for k, v := range f.Secrets {
		s.Secrets[k] = v
	}
	s.Users = f.Users
	o := f.Origin
	o.Warnings = append(append([]string{}, f.Warnings...), f.Risky...)
	o.State, o.ImportedAt = state.OriginImported, time.Now()
	s.Origin = &o
	if err := m.AutoDefaults(e.Env, s); err != nil {
		return err
	}
	e.St.Services[f.ID] = s
	return nil
}

// MigrateOpts — параметры переноса.
type MigrateOpts struct {
	Force      bool // перенос, несмотря на предупреждения Risky
	NoRollback bool // не откатывать автоматически при неудачной проверке
}

// AdoptMigrate переводит импортированные сервисы под vpnstack:
//  1. подготовка без простоя — резервная копия, сертификаты и данные, скачивание программ;
//  2. переключение — остановка старых установок и запуск под vpnstack с теми же ключами;
//  3. проверка — юниты работают, порты слушаются; иначе автоматический откат.
func (e *Engine) AdoptMigrate(ids []string, o MigrateOpts) error {
	e.Lock()
	defer e.Unlock()
	if err := e.Init(); err != nil {
		return err
	}
	set, err := e.migrationSet(ids)
	if err != nil {
		return err
	}
	e.refreshImported(set, o.Force)
	for _, id := range set {
		e.St.Svc(id).Enabled = true
	}
	set, err = e.closeOverPorts(set)
	if err != nil {
		for _, id := range set {
			e.St.Svc(id).Enabled = false
		}
		e.refresh()
		return err
	}
	e.refresh() // план с учётом переносимых: нужны ли Caddy и общий вход
	sys.Logf("==> Перенос: %s", strings.Join(set, ", "))

	// 1. Подготовка — старые установки продолжают работать.
	ts := time.Now().Format("20060102-150405")
	for _, id := range set {
		s := e.St.Svc(id)
		if err := backupOrigin(id, s.Origin, ts); err != nil {
			sys.Logf("[!] резервная копия %s: %v", id, err)
		}
		if err := prepareFiles(id, s, false); err != nil {
			return e.abortPrepare(set, fmt.Errorf("%s: подготовка файлов: %w", id, err))
		}
	}
	if err := e.prefetch(set); err != nil {
		return e.abortPrepare(set, err)
	}
	_ = e.St.Save()

	// 2. Переключение.
	sys.Logf("==> Переключение: останавливаю старые установки")
	t0 := time.Now()
	for _, id := range set {
		stopOrigin(e.St.Svc(id).Origin)
	}
	e.waitPortsFree(set, 15*time.Second)
	err = func() error {
		for _, id := range set {
			if err := prepareFiles(id, e.St.Svc(id), true); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
		}
		if err := e.infra(); err != nil {
			return fmt.Errorf("служебные компоненты: %w", err)
		}
		modules.EnsureUser("caddy")
		_, _ = sys.Run("chown", "-R", "caddy:caddy", filepath.Dir(modules.CaddyStorageDir()))
		for _, id := range set {
			m, _ := module.Get(id)
			s := e.St.Svc(id)
			sys.Logf("==> Запуск %s под vpnstack", m.Title())
			if err := m.Install(e.Env, s); err != nil {
				s.Error = err.Error()
				return fmt.Errorf("%s: %w", m.Title(), err)
			}
			s.Installed, s.Error, s.InstalledAt = true, "", time.Now()
		}
		// 3. Проверка.
		return e.probe(append(e.coreIDs(), set...), 40*time.Second)
	}()
	if err != nil {
		if o.NoRollback {
			_ = e.St.Save()
			return fmt.Errorf("перенос не удался: %w\nАвтоматический откат отключён; вернуть старую установку: vpnstack adopt rollback %s", err, strings.Join(set, " "))
		}
		sys.Logf("[!] %v", err)
		sys.Logf("==> Откат: возвращаю старые установки")
		rerr := e.rollback(set)
		if rerr != nil {
			return fmt.Errorf("перенос не удался: %w\nОткат тоже с ошибкой: %v", err, rerr)
		}
		return fmt.Errorf("перенос не удался, выполнен откат — снова работает старая установка (простой %s):\n%w", time.Since(t0).Round(time.Second), err)
	}
	for _, id := range set {
		s := e.St.Svc(id)
		s.Origin.State, s.Origin.MigratedAt = state.OriginMigrated, time.Now()
	}
	sys.Logf("==> Готово. Простой при переключении: %s", time.Since(t0).Round(time.Second))
	sys.Logf("    Старые установки остановлены, но не удалены: откат — vpnstack adopt rollback, удаление — vpnstack adopt cleanup")
	return e.St.Save()
}

func (e *Engine) migrationSet(ids []string) ([]string, error) {
	var set []string
	if len(ids) == 0 || ids[0] == "all" {
		for id, s := range e.St.Services {
			if s.Origin != nil && (s.Origin.State == state.OriginImported || s.Origin.State == state.OriginRolledBack) {
				set = append(set, id)
			}
		}
		if len(set) == 0 {
			return nil, fmt.Errorf("нет импортированных установок: сначала vpnstack adopt import")
		}
	} else {
		for _, id := range ids {
			s := e.St.Services[id]
			if s == nil || s.Origin == nil {
				return nil, fmt.Errorf("%s не импортирован: vpnstack adopt import %s", id, id)
			}
			if s.Origin.State != state.OriginImported && s.Origin.State != state.OriginRolledBack {
				return nil, fmt.Errorf("%s: состояние «%s» — переносить нечего", id, s.Origin.State)
			}
			set = append(set, id)
		}
	}
	return orderIDs(set), nil
}

func orderIDs(ids []string) []string {
	pos := map[string]int{}
	for i, m := range module.All() {
		pos[m.ID()] = i
	}
	sort.SliceStable(ids, func(i, j int) bool { return pos[ids[i]] < pos[ids[j]] })
	return ids
}

// refreshImported — перед переносом перечитывает старые установки: пользователи,
// добавленные в них после импорта, тоже переносятся.
func (e *Engine) refreshImported(set []string, force bool) {
	r := adopt.Scan()
	for _, id := range set {
		s := e.St.Svc(id)
		fs, err := pick(r, []string{id})
		if err != nil || len(fs[0].Blocking) > 0 {
			continue
		}
		f := fs[0]
		var keep []*state.User
		for _, u := range s.Users {
			if u.Data["imported"] != "1" {
				keep = append(keep, u)
			}
		}
		fresh := 0
		for _, u := range f.Users {
			if s.FindUser(u.Name) == nil {
				fresh++
			}
			if su := s.FindUser(u.Name); su != nil && su.Data["imported"] != "1" {
				continue
			}
			keep = append(keep, u)
		}
		s.Users = keep
		if fresh > 0 {
			sys.Logf("    %s: в старой установке появилось пользователей: %d — перенесены", id, fresh)
		}
	}
}

// closeOverPorts: порты, занятые другими перенимаемыми установками, освободятся при
// переключении — такие установки добавляются в перенос. Остальные занятые порты — ошибка.
func (e *Engine) closeOverPorts(set []string) ([]string, error) {
	for round := 0; round < 5; round++ {
		r := e.Plan()
		in := map[string]bool{}
		for _, id := range set {
			in[id] = true
		}
		var fatal []string
		added := false
		for _, p := range r.Problems {
			if !p.Fatal {
				continue
			}
			if p.Kind != "port_busy" {
				fatal = append(fatal, p.Msg)
				continue
			}
			holder := ""
			for id, s := range e.St.Services {
				if s.Origin != nil && s.Origin.State != state.OriginMigrated && s.Origin.State != state.OriginCleaned &&
					(s.Origin.HoldsPort(p.Proto, p.Port) || s.Origin.HasUnit(p.Unit)) {
					holder = id
				}
			}
			switch {
			case holder == "":
				fatal = append(fatal, p.Msg+" — это не перенимаемая установка: остановите её или смените порт")
			case !in[holder]:
				sys.Logf("    %s держит %s/%d — переношу его вместе с остальными", holder, p.Proto, p.Port)
				e.St.Svc(holder).Enabled = true
				set = append(set, holder)
				in[holder] = true
				added = true
			}
		}
		if len(fatal) > 0 {
			return set, fmt.Errorf("перенос невозможен:\n  • %s", strings.Join(fatal, "\n  • "))
		}
		if !added {
			return orderIDs(set), nil
		}
	}
	return orderIDs(set), nil
}

func (e *Engine) abortPrepare(set []string, err error) error {
	for _, id := range set {
		e.St.Svc(id).Enabled = false
	}
	e.refresh()
	_ = e.St.Save()
	return fmt.Errorf("подготовка не удалась (старые установки не тронуты): %w", err)
}

func (e *Engine) coreIDs() []string {
	var ids []string
	if e.last.NeedCaddy {
		ids = append(ids, "caddy")
	}
	if e.last.NeedEdge {
		ids = append(ids, "edge")
	}
	return ids
}

// prefetch скачивает всё заранее, чтобы переключение заняло секунды.
func (e *Engine) prefetch(set []string) error {
	ids := append(e.coreIDs(), set...)
	for _, id := range ids {
		m, _ := module.Get(id)
		f, ok := m.(module.Fetcher)
		if !ok {
			continue
		}
		sys.Logf("==> Подготовка %s (скачивание)", m.Title())
		if err := f.Prefetch(e.Env, e.St.Svc(id)); err != nil {
			return fmt.Errorf("%s: %w", m.Title(), err)
		}
	}
	return nil
}

func backupOrigin(id string, o *state.Origin, ts string) error {
	dir := filepath.Join(AdoptDir, id+"-"+ts)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	o.BackupDir = dir
	for _, c := range o.Configs {
		if sys.Exists(c) {
			_, _ = sys.Run("cp", "-a", "--parents", c, dir)
		}
	}
	for _, u := range o.Units {
		if out, err := sys.Output("systemctl", "cat", u); err == nil {
			_ = os.WriteFile(filepath.Join(dir, u), []byte(out), 0o600)
		}
	}
	for _, c := range o.Containers {
		if out, err := sys.Output("docker", "inspect", c); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "docker-"+c[:12]+".json"), []byte(out), 0o600)
		}
	}
	if d := o.Files["fptn_data"]; d != "" {
		_, _ = sys.Run("cp", "-a", d, filepath.Join(dir, "fptn-data"))
	}
	return nil
}

// prepareFiles переносит сертификаты и данные старой установки. cutover — повтор
// после остановки старой (для файлов, которые могли измениться: users.list).
func prepareFiles(id string, s *state.Service, cutover bool) error {
	o := s.Origin
	store := modules.CaddyStorageDir()
	switch id {
	case "hysteria":
		if cutover {
			return nil
		}
		if d := o.Files["certmagic"]; d != "" {
			issuer := filepath.Base(filepath.Dir(d))
			dst := filepath.Join(store, "certificates", issuer)
			if err := os.MkdirAll(dst, 0o750); err != nil {
				return err
			}
			if _, err := sys.Run("cp", "-a", "-n", d, dst+"/"); err != nil {
				return err
			}
		}
		if c, k := o.Files["cert"], o.Files["key"]; c != "" && k != "" {
			cert, key := modules.HysteriaCertPaths()
			_ = os.MkdirAll(filepath.Dir(cert), 0o750)
			for _, p := range [][2]string{{c, cert}, {k, key}} {
				b, err := os.ReadFile(p[0])
				if err != nil {
					return err
				}
				if err := sys.WriteFileAtomic(p[1], b, 0o640); err != nil {
					return err
				}
			}
		}
	case "tgwp":
		if src := o.Files["caddy_storage"]; src != "" && !cutover && sys.Exists(filepath.Join(src, "certificates")) {
			if err := os.MkdirAll(store, 0o750); err != nil {
				return err
			}
			if _, err := sys.Run("cp", "-a", "-n", filepath.Join(src, "certificates"), store+"/"); err != nil {
				return err
			}
		}
	case "fptn":
		src := o.Files["fptn_data"]
		if src == "" {
			return nil
		}
		dst := modules.FPTNDataDir()
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		if cutover {
			if sys.Exists(filepath.Join(src, "users.list")) {
				_, err := sys.Run("cp", "-a", filepath.Join(src, "users.list"), dst+"/")
				return err
			}
			return nil
		}
		_, err := sys.Run("cp", "-a", src+"/.", dst+"/")
		return err
	}
	return nil
}

// stopOrigin останавливает старую установку так, чтобы её можно было вернуть.
func stopOrigin(o *state.Origin) {
	if o.Files == nil {
		o.Files = map[string]string{}
	}
	for _, u := range o.Units {
		st, _ := sys.Output("systemctl", "is-enabled", u)
		o.Files["enabled:"+u] = strings.TrimSpace(st)
		_ = sys.Systemctl("disable", "--now", u)
	}
	for _, c := range o.Containers {
		pol, _ := sys.Output("docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", c)
		o.Files["restart:"+c] = strings.TrimSpace(pol)
		_, _ = sys.Run("docker", "update", "--restart=no", c)
		_, _ = sys.Run("docker", "stop", c)
	}
	if pid := o.Files["pid"]; pid != "" && o.Kind == "process" {
		_, _ = sys.Run("kill", pid)
	}
}

// startOrigin возвращает старую установку.
func startOrigin(o *state.Origin) error {
	var errs []string
	for _, u := range o.Units {
		if o.Files["enabled:"+u] == "enabled" {
			_ = sys.Systemctl("enable", u)
		}
		if err := sys.Systemctl("start", u); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, c := range o.Containers {
		if pol := o.Files["restart:"+c]; pol != "" {
			_, _ = sys.Run("docker", "update", "--restart="+pol, c)
		}
		if _, err := sys.Run("docker", "start", c); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if cmd := o.Files["cmdline"]; cmd != "" && o.Kind == "process" {
		args := append([]string{"--unit=vpnstack-adopt-restore-" + sys.RandHex(3), "--"}, strings.Split(cmd, "\x00")...)
		if _, err := sys.Run("systemd-run", args...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (e *Engine) waitPortsFree(set []string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		busy := false
		ls := sys.Listeners()
		for _, id := range set {
			o := e.St.Svc(id).Origin
			for _, l := range ls {
				if o.HoldsPort(l.Proto, l.Port) && !strings.HasPrefix(sys.UnitOfPID(l.PID), "vpnstack") {
					busy = true
				}
			}
		}
		if !busy {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// rollback останавливает перенесённые сервисы и возвращает старые установки.
func (e *Engine) rollback(set []string) error {
	for _, id := range set {
		m, _ := module.Get(id)
		s := e.St.Svc(id)
		if s.Origin == nil || !s.Origin.InPlace {
			_ = m.Remove(e.Env, s, false)
		}
		s.Enabled, s.Installed = false, false
	}
	var errs []string
	if err := e.infra(); err != nil {
		errs = append(errs, "служебные компоненты: "+err.Error())
	}
	e.waitOursFree(set, 10*time.Second)
	for _, id := range set {
		s := e.St.Svc(id)
		if err := startOrigin(s.Origin); err != nil {
			errs = append(errs, id+": "+err.Error())
		}
		s.Origin.State = state.OriginRolledBack
	}
	_ = e.St.Save()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// waitOursFree ждёт, пока сервисы vpnstack отпустят порты старых установок.
func (e *Engine) waitOursFree(set []string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		busy := ""
		for _, l := range sys.Listeners() {
			for _, id := range set {
				if e.St.Svc(id).Origin.HoldsPort(l.Proto, l.Port) && strings.HasPrefix(sys.UnitOfPID(l.PID), "vpnstack") {
					busy = fmt.Sprintf("%s/%d", l.Proto, l.Port)
				}
			}
		}
		if busy == "" {
			return
		}
		if time.Now().Add(300 * time.Millisecond).After(deadline) {
			sys.Logf("[!] порт %s всё ещё занят сервисом vpnstack (нужен другим включённым сервисам?) — старая установка может не запуститься", busy)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// AdoptRollback возвращает старые установки после переноса.
func (e *Engine) AdoptRollback(ids []string) error {
	e.Lock()
	defer e.Unlock()
	var set []string
	for id, s := range e.St.Services {
		if s.Origin == nil || s.Origin.State != state.OriginMigrated {
			continue
		}
		if len(ids) == 0 || ids[0] == "all" || contains(ids, id) {
			set = append(set, id)
		}
	}
	if len(set) == 0 {
		return fmt.Errorf("нет перенесённых сервисов для отката (откат после adopt cleanup невозможен)")
	}
	sys.Logf("==> Откат: %s", strings.Join(orderIDs(set), ", "))
	return e.rollback(orderIDs(set))
}

// AdoptCleanup удаляет остановленные старые установки (контейнеры); юниты остаются
// выключенными, файлы — в резервной копии. После этого откат невозможен.
func (e *Engine) AdoptCleanup(ids []string) error {
	e.Lock()
	defer e.Unlock()
	n := 0
	for id, s := range e.St.Services {
		if s.Origin == nil || s.Origin.State != state.OriginMigrated {
			continue
		}
		if !(len(ids) == 0 || ids[0] == "all" || contains(ids, id)) {
			continue
		}
		for _, c := range s.Origin.Containers {
			if _, err := sys.Run("docker", "rm", c); err != nil {
				sys.Logf("[!] docker rm %s: %v", c[:12], err)
			}
		}
		for _, u := range s.Origin.Units {
			_ = sys.Systemctl("mask", u) // чтобы старая установка не запустилась случайно
		}
		s.Origin.State = state.OriginCleaned
		sys.Logf("%s: старая установка удалена (резервная копия: %s)", id, s.Origin.BackupDir)
		n++
	}
	if n == 0 {
		return fmt.Errorf("нечего удалять: нет перенесённых сервисов")
	}
	return e.St.Save()
}

// probe ждёт, пока сервисы заработают: юниты активны, нужные порты слушаются.
func (e *Engine) probe(ids []string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		var bad []string
		ls := sys.Listeners()
		for _, id := range ids {
			m, ok := module.Get(id)
			if !ok {
				continue
			}
			s := e.St.Svc(id)
			st := m.Status(e.Env, s)
			if st.State != "running" {
				bad = append(bad, fmt.Sprintf("%s: %s %s", m.Title(), st.State, st.Detail))
				continue
			}
			if id == "fptn" { // порты Docker могут публиковаться без docker-proxy
				continue
			}
			for _, n := range m.Needs(e.Env, s) {
				if n.Port == 0 || n.Redirect {
					continue
				}
				if !listening(ls, n.Proto, n.Port) {
					bad = append(bad, fmt.Sprintf("%s: не слушается %s/%d (%s)", m.Title(), n.Proto, n.Port, n.Purpose))
				}
			}
		}
		if len(bad) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("проверка не прошла:\n  • %s", strings.Join(bad, "\n  • "))
		}
		time.Sleep(time.Second)
	}
}

func listening(ls []sys.Listener, proto string, port int) bool {
	for _, l := range ls {
		if l.Proto == proto && l.Port == port {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// MigrateSummary — что именно произойдёт при переносе (для подтверждения).
func (e *Engine) MigrateSummary(ids []string) string {
	set, err := e.migrationSet(ids)
	if err != nil {
		return "[!] " + err.Error()
	}
	var b strings.Builder
	b.WriteString("Будет перенесено под vpnstack:\n")
	for _, id := range set {
		s := e.St.Svc(id)
		title := id
		if m, ok := module.Get(id); ok {
			title = m.Title()
		}
		o := s.Origin
		fmt.Fprintf(&b, "  • %s — %s\n", title, o.Source)
		if len(o.Ports) > 0 {
			fmt.Fprintf(&b, "      порты: %s (останутся теми же)\n", strings.Join(o.Ports, ", "))
		}
		fmt.Fprintf(&b, "      пользователей: %d — ключи, пароли и ссылки не меняются\n", len(s.Users))
		var stop []string
		stop = append(stop, o.Units...)
		for _, c := range o.Containers {
			if len(c) > 12 {
				c = c[:12]
			}
			stop = append(stop, "docker "+c)
		}
		if len(stop) > 0 {
			fmt.Fprintf(&b, "      будет остановлено: %s\n", strings.Join(stop, ", "))
		}
		for _, w := range o.Warnings {
			fmt.Fprintf(&b, "      [!] %s\n", w)
		}
	}
	b.WriteString("Клиенты переподключатся один раз (обычно 5–20 с). При сбое — автоматический откат.\n")
	b.WriteString("Старые установки не удаляются до vpnstack adopt cleanup.")
	return b.String()
}
