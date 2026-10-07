// Package adopt находит на сервере сервисы, установленные без vpnstack (вручную,
// официальными скриптами, в Docker, через 3x-ui/Amnezia), и считывает их настройки и
// пользователей так, чтобы после переноса под vpnstack у клиентов ничего не менялось:
// те же порты, ключи, секреты, UUID, пароли и ссылки.
//
// Сканирование только читает файлы и состояние процессов; остановка старых установок
// и запуск под vpnstack — в core (Migrate) с автоматическим откатом.
package adopt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Found — найденная установка, готовая к импорту в модуль ID.
type Found struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Origin    state.Origin      `json:"origin"`
	Params    map[string]string `json:"params"`
	Secrets   map[string]string `json:"-"`
	Users     []*state.User     `json:"-"`
	UserNames []string          `json:"users"`
	Warnings  []string          `json:"warnings,omitempty"`
	Risky     []string          `json:"risky,omitempty"`    // перенос возможен только с --force
	Blocking  []string          `json:"blocking,omitempty"` // перенос невозможен
	Status    string            `json:"status,omitempty"`   // заполняет core: new | imported | migrated…
}

// Foreign — посторонняя программа на портах, нужных стеку.
type Foreign struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Unit    string `json:"unit,omitempty"`
	Hint    string `json:"hint"`
}

// Report — итог сканирования.
type Report struct {
	Found   []*Found  `json:"found"`
	Foreign []Foreign `json:"foreign,omitempty"`
	Notes   []string  `json:"notes,omitempty"`
}

// Пути и команды — переменные, чтобы тесты могли подменить окружение.
var (
	procDir  = "/proc"
	hostRoot = ""
	run      = sys.Output
)

func hostPath(p string) string { return hostRoot + p }

func readHost(p string) ([]byte, error) { return os.ReadFile(hostPath(p)) }

type proc struct {
	PID  int
	Exe  string // базовое имя исполняемого файла
	Args []string
	Unit string // systemd-юнит (service/scope) по cgroup
}

// path — путь к файлу так, как его видит процесс (в т. ч. внутри контейнера).
func (p proc) path(f string) string {
	if filepath.IsAbs(f) {
		return filepath.Join(procDir, strconv.Itoa(p.PID), "root", f)
	}
	return filepath.Join(procDir, strconv.Itoa(p.PID), "cwd", f)
}

func (p proc) read(f string) ([]byte, error) { return os.ReadFile(p.path(f)) }

// env — переменная окружения процесса.
func (p proc) env(key string) string {
	b, _ := os.ReadFile(filepath.Join(procDir, strconv.Itoa(p.PID), "environ"))
	for _, kv := range strings.Split(string(b), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// container — ID Docker-контейнера процесса (по cgroup), если он в контейнере.
func (p proc) container() string {
	if strings.HasPrefix(p.Unit, "docker-") && strings.HasSuffix(p.Unit, ".scope") {
		return strings.TrimSuffix(strings.TrimPrefix(p.Unit, "docker-"), ".scope")
	}
	b, _ := os.ReadFile(filepath.Join(procDir, strconv.Itoa(p.PID), "cgroup"))
	if m := regexp.MustCompile(`docker[-/]([0-9a-f]{64})`).FindStringSubmatch(string(b)); m != nil {
		return m[1]
	}
	return ""
}

// flag — значение флага (-c x, --config=x, -config x).
func (p proc) flag(names ...string) string {
	for i, a := range p.Args {
		for _, n := range names {
			if a == n && i+1 < len(p.Args) {
				return p.Args[i+1]
			}
			if v, ok := strings.CutPrefix(a, n+"="); ok {
				return v
			}
		}
	}
	return ""
}

func procs() []proc {
	ents, _ := os.ReadDir(procDir)
	var out []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procDir, e.Name(), "cmdline"))
		if err != nil || len(b) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		exe, _ := os.Readlink(filepath.Join(procDir, e.Name(), "exe"))
		if exe == "" {
			exe = args[0]
		}
		exe = strings.TrimSuffix(filepath.Base(exe), " (deleted)")
		p := proc{PID: pid, Exe: exe, Args: args[1:]}
		if cg, err := os.ReadFile(filepath.Join(procDir, e.Name(), "cgroup")); err == nil {
			for _, part := range strings.Split(strings.TrimSpace(string(cg)), "/") {
				if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
					p.Unit = part
				}
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// ours — процесс уже под управлением vpnstack.
func ours(p proc) bool { return strings.HasPrefix(p.Unit, "vpnstack-") }

// originOf заполняет, как остановить и вернуть процесс.
func originOf(p proc, title string) state.Origin {
	o := state.Origin{Source: title, State: state.OriginImported, ImportedAt: time.Now(), Files: map[string]string{}}
	switch c := p.container(); {
	case c != "":
		o.Kind = "docker"
		o.Containers = []string{c}
		o.Source += " (Docker " + c[:12] + ")"
	case strings.HasSuffix(p.Unit, ".service") && !strings.HasPrefix(p.Unit, "user@"):
		o.Kind = "systemd"
		o.Units = []string{p.Unit}
		o.Source += " (" + p.Unit + ")"
	default:
		o.Kind = "process"
		o.Files["cmdline"] = strings.Join(append([]string{exeOf(p)}, p.Args...), "\x00")
		o.Files["pid"] = strconv.Itoa(p.PID)
		o.Source += fmt.Sprintf(" (процесс %d без systemd)", p.PID)
	}
	return o
}

func exeOf(p proc) string {
	exe, _ := os.Readlink(filepath.Join(procDir, strconv.Itoa(p.PID), "exe"))
	return strings.TrimSuffix(exe, " (deleted)")
}

func newFound(id, title string, o state.Origin) *Found {
	return &Found{ID: id, Title: title, Origin: o, Params: map[string]string{}, Secrets: map[string]string{}}
}

func (f *Found) addUser(name string, data map[string]string) {
	name = uniqueName(f.Users, sanitizeName(name, len(f.Users)+1))
	if data == nil {
		data = map[string]string{}
	}
	data["imported"] = "1"
	f.Users = append(f.Users, &state.User{Name: name, Created: time.Now(), Data: data, Note: "перенят из " + f.Origin.Source})
	f.UserNames = append(f.UserNames, name)
}

func (f *Found) port(proto string, port int) {
	if port <= 0 {
		return
	}
	k := fmt.Sprintf("%s/%d", proto, port)
	for _, p := range f.Origin.Ports {
		if p == k {
			return
		}
	}
	f.Origin.Ports = append(f.Origin.Ports, k)
}

var nameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeName приводит имя клиента к правилам vpnstack (латиница, цифры, - _ .).
func sanitizeName(s string, n int) string {
	s = strings.TrimSpace(s)
	if at := strings.Index(s, "@"); at > 0 && !strings.Contains(s[:at], " ") {
		s = s[:at] + "_" + s[at+1:]
	}
	s = strings.Trim(nameRe.ReplaceAllString(s, "_"), "_.-")
	if len(s) > 32 {
		s = s[:32]
	}
	if s == "" {
		s = fmt.Sprintf("user%d", n)
	}
	return s
}

func uniqueName(users []*state.User, name string) string {
	taken := map[string]bool{}
	for _, u := range users {
		taken[strings.ToLower(u.Name)] = true
	}
	if !taken[strings.ToLower(name)] {
		return name
	}
	for i := 2; ; i++ {
		c := fmt.Sprintf("%s-%d", name, i)
		if len(c) > 32 {
			c = fmt.Sprintf("%s-%d", name[:32-len(fmt.Sprint(i))-1], i)
		}
		if !taken[strings.ToLower(c)] {
			return c
		}
	}
}

func portOf(listen string) int {
	listen = strings.TrimSpace(listen)
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		listen = listen[i+1:]
	}
	n, _ := strconv.Atoi(listen)
	return n
}

func anyInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return 0
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Scan ищет все поддерживаемые установки.
func Scan() *Report {
	ps := procs()
	r := &Report{}
	for _, f := range [][]*Found{scanHysteria(ps), scanXray(ps), scanTelemt(ps), scanAWG(ps), scanFPTN(), scanTGWP()} {
		r.Found = append(r.Found, f...)
	}
	r.Foreign = foreign(r, ps)
	for _, p := range ps {
		if ours(p) {
			continue
		}
		switch {
		case p.Exe == "sing-box":
			r.Notes = append(r.Notes, fmt.Sprintf("sing-box (pid %d): автоматический перенос не поддерживается — его порты учтены в проверке конфликтов", p.PID))
		case p.Exe == "marzban" || strings.Contains(strings.Join(p.Args, " "), "marzban"):
			r.Notes = append(r.Notes, "Marzban: пользователи хранятся в его базе — переносите их по одному (vpnstack users xray add NAME uuid=…)")
		}
	}
	return r
}

// foreign — кто ещё держит порты общего входа и Caddy (80, 443).
func foreign(r *Report, ps []proc) []Foreign {
	known := map[int]bool{}
	for _, p := range ps {
		for _, f := range r.Found {
			if f.Origin.HasUnit(p.Unit) || (p.container() != "" && f.Origin.HasUnit("docker-"+p.container()+".scope")) {
				known[p.PID] = true
			}
		}
		if ours(p) {
			known[p.PID] = true
		}
	}
	var out []Foreign
	seen := map[string]bool{}
	for _, l := range sys.Listeners() {
		if !(l.Proto == "tcp" && (l.Port == 80 || l.Port == 443)) && !(l.Proto == "udp" && l.Port == 443) {
			continue
		}
		held := false
		for _, f := range r.Found {
			held = held || f.Origin.HoldsPort(l.Proto, l.Port)
		}
		k := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if held || known[l.PID] || seen[k] {
			continue
		}
		seen[k] = true
		fo := Foreign{Proto: l.Proto, Port: l.Port, Process: l.Process, PID: l.PID, Unit: sys.UnitOfPID(l.PID)}
		switch l.Process {
		case "nginx", "apache2", "httpd", "caddy", "haproxy":
			fo.Hint = fmt.Sprintf("веб-сервер: переведите его сайты на другой порт (например, 127.0.0.1:8443) и добавьте маршрут: vpnstack route add <домен> 127.0.0.1:8443 — " +
				"общий вход 443 будет передавать ему соединения по SNI без расшифровки")
		case "docker-proxy":
			fo.Hint = "порт опубликован Docker-контейнером: остановите его или опубликуйте на другом порту"
		default:
			fo.Hint = "остановите программу или перенесите её на другой порт"
		}
		out = append(out, fo)
	}
	return out
}

func sortStrings(s []string) { sort.Strings(s) }
