// vpnstack — оркестратор VPN/прокси-сервисов на одном сервере.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lineSence/vpnstack/internal/core"
	"github.com/lineSence/vpnstack/internal/edge"
	"github.com/lineSence/vpnstack/internal/module"
	_ "github.com/lineSence/vpnstack/internal/modules"
	"github.com/lineSence/vpnstack/internal/ota"
	"github.com/lineSence/vpnstack/internal/panel"
	"github.com/lineSence/vpnstack/internal/stats"
	"github.com/lineSence/vpnstack/internal/sys"
	"github.com/lineSence/vpnstack/internal/tui"
	"github.com/lineSence/vpnstack/internal/version"
)

const usage = `vpnstack %s — VPN/прокси-стек на одном сервере

Использование:
  vpnstack                         интерактивное меню
  vpnstack install [svc...] [--set svc.key=value ...]
                                   установка (без аргументов — мастер)
  vpnstack set <svc> key=value...  изменить параметры сервиса
  vpnstack set key=value...        общие: public_ip, email, edge_mode (sni|ports), channel, ota_auto
  vpnstack remove <svc> [--purge]  удалить сервис
  vpnstack status [--json]         состояние
  vpnstack plan                    проверка портов/SNI/DNS
  vpnstack users <svc> [list|add NAME|del NAME|show NAME]
  vpnstack links <svc>             общие ссылки сервиса (TG WEB proxy)
  vpnstack update [svc|all]        обновить сервисы до последних версий
  vpnstack self-update [--check] [--tag vX.Y.Z]
                                   обновить сам vpnstack (подписанные релизы)
  vpnstack panel passwd [пароль] | panel totp on|off | panel url
  vpnstack modules                 список модулей (встроенные и из /etc/vpnstack/modules.d)
  vpnstack doctor                  диагностика
  vpnstack version

Служебные: serve (панель+сбор статистики), edge (общий вход 443), setup, ota-guard
Сервисы: %s
`

// loadEnv читает /etc/vpnstack/env (KEY=VALUE): токен GitHub для приватного репозитория и т. п.
func loadEnv() {
	b, err := os.ReadFile("/etc/vpnstack/env")
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && !strings.HasPrefix(k, "#") && os.Getenv(k) == "" {
			os.Setenv(k, strings.Trim(v, `"'`))
		}
	}
	sys.GitHubToken = os.Getenv("VPNSTACK_GITHUB_TOKEN")
}

func main() {
	loadEnv()
	if errs := module.LoadExternal(); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "модуль:", e)
		}
	}
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("vpnstack %s (%s)\n", version.Version, version.Commit)
		return
	case "help", "--help", "-h":
		fmt.Printf(usage, version.Version, strings.Join(core.IDs(), ", "))
		return
	case "edge":
		err = edge.Run()
	case "ota-guard":
		err = ota.Guard()
	default:
		if os.Geteuid() != 0 {
			fail(fmt.Errorf("нужны права root (sudo vpnstack ...)"))
		}
		err = run(cmd, args)
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "\033[31m[x]\033[0m", err)
	os.Exit(1)
}

func open() *core.Engine {
	e, err := core.Open()
	if err != nil {
		fail(err)
	}
	return e
}

func kv(args []string) (map[string]string, []string) {
	m := map[string]string{}
	var rest []string
	for _, a := range args {
		if k, v, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(a, "-") {
			m[k] = v
		} else {
			rest = append(rest, a)
		}
	}
	return m, rest
}

func run(cmd string, args []string) error {
	sys.Log = os.Stdout
	switch cmd {
	case "", "menu":
		return tui.Run(open())
	case "install":
		e := open()
		var ids []string
		params := map[string]map[string]string{}
		for i := 0; i < len(args); i++ {
			if args[i] == "--set" && i+1 < len(args) {
				i++
				k, v, _ := strings.Cut(args[i], "=")
				id, key, ok := strings.Cut(k, ".")
				if !ok {
					return fmt.Errorf("--set ожидает svc.key=value")
				}
				if params[id] == nil {
					params[id] = map[string]string{}
				}
				params[id][key] = v
				continue
			}
			ids = append(ids, args[i])
		}
		if len(ids) == 0 {
			tui.Wizard(e)
			return nil
		}
		if err := e.Init(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := e.Prepare(id, params[id]); err != nil {
				return err
			}
		}
		for _, id := range ids {
			if err := e.Install(id, params[id]); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
			printLinks(e, id)
		}
		return nil
	case "set":
		e := open()
		if len(args) > 0 && !strings.Contains(args[0], "=") {
			p, _ := kv(args[1:])
			return e.Reconfigure(args[0], p)
		}
		p, _ := kv(args)
		st := e.St
		for k, v := range p {
			switch k {
			case "public_ip":
				st.PublicIP = v
			case "email":
				st.Email = v
			case "edge_mode":
				if v != "sni" && v != "ports" {
					return fmt.Errorf("edge_mode: sni или ports")
				}
				st.EdgeMode = v
			case "channel":
				st.Channel = v
			case "ota_auto":
				st.OTA.Auto = v == "true" || v == "1"
			case "ota_channel":
				st.OTA.Channel = v
			default:
				return fmt.Errorf("неизвестный параметр %s", k)
			}
		}
		if err := st.Save(); err != nil {
			return err
		}
		return e.ApplyAll()
	case "remove", "uninstall":
		if len(args) == 0 {
			return fmt.Errorf("укажите сервис")
		}
		purge := len(args) > 1 && args[1] == "--purge"
		return open().Remove(args[0], purge)
	case "status":
		e := open()
		if len(args) > 0 && args[0] == "--json" {
			return json.NewEncoder(os.Stdout).Encode(e.Services())
		}
		tui.Status(e)
		return nil
	case "plan":
		r := open().Plan()
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	case "users":
		return users(open(), args)
	case "links":
		if len(args) == 0 {
			return fmt.Errorf("укажите сервис")
		}
		return printLinks(open(), args[0])
	case "update":
		e := open()
		target := "all"
		if len(args) > 0 {
			target = args[0]
		}
		for _, s := range e.Services() {
			if s.Installed && (target == "all" || target == s.ID) {
				if err := e.Update(s.ID); err != nil {
					fmt.Fprintf(os.Stderr, "[x] %s: %v\n", s.ID, err)
				}
			}
		}
		return nil
	case "self-update":
		e := open()
		ch := e.St.OTA.Channel
		tag := ""
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--check":
				in, err := ota.Check(ch)
				if err != nil {
					return err
				}
				fmt.Printf("установлена %s, последняя %s, обновление: %v\n", in.Current, in.Latest, in.Available)
				return nil
			case "--tag":
				if i+1 < len(args) {
					tag = args[i+1]
					i++
				}
			}
		}
		t, err := ota.Apply(ch, tag)
		if err != nil {
			return err
		}
		fmt.Println("установлена", t)
		ota.RestartServices()
		return nil
	case "panel":
		return panelCmd(open(), args)
	case "modules":
		for _, m := range module.All() {
			kind := "встроенный"
			if m.Core() {
				kind = "служебный"
			}
			if _, ok := m.(*module.External); ok {
				kind = "внешний"
			}
			fmt.Printf("%-10s %-26s %-10s %s\n", m.ID(), m.Title(), kind, m.Description())
		}
		return nil
	case "doctor":
		return doctor(open())
	case "serve":
		return serve()
	case "setup":
		return setup()
	}
	return fmt.Errorf("неизвестная команда %q (vpnstack help)", cmd)
}

func printLinks(e *core.Engine, id string) error {
	s := e.St.Svc(id)
	name := ""
	if len(s.Users) > 0 {
		name = s.Users[0].Name
	}
	arts, err := e.Artifacts(id, name)
	if err != nil {
		return err
	}
	for _, a := range arts {
		fmt.Printf("\n%s:\n%s\n", a.Title, a.Value)
	}
	return nil
}

func users(e *core.Engine, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("vpnstack users <svc> [list|add NAME|del NAME|show NAME]")
	}
	id, act := args[0], "list"
	if len(args) > 1 {
		act = args[1]
	}
	name := ""
	if len(args) > 2 {
		name = args[2]
	}
	switch act {
	case "list":
		for _, u := range e.St.Svc(id).Users {
			fmt.Printf("%-24s %s\n", u.Name, u.Created.Format("2006-01-02"))
		}
	case "add":
		u, err := e.AddUser(id, name, nil)
		if err != nil {
			return err
		}
		name = u.Name
		fallthrough
	case "show":
		arts, err := e.Artifacts(id, name)
		if err != nil {
			return err
		}
		for _, a := range arts {
			fmt.Printf("\n%s:\n%s\n", a.Title, a.Value)
		}
	case "del":
		return e.DelUser(id, name)
	default:
		return fmt.Errorf("неизвестное действие %s", act)
	}
	return nil
}

func panelCmd(e *core.Engine, args []string) error {
	if len(args) == 0 {
		args = []string{"url"}
	}
	switch args[0] {
	case "passwd":
		pw := sys.RandHex(8)
		if len(args) > 1 {
			pw = args[1]
		}
		h, err := panel.HashPassword(pw)
		if err != nil {
			return err
		}
		e.St.Panel.PassHash = h
		if err := e.St.Save(); err != nil {
			return err
		}
		fmt.Printf("логин: %s\nпароль: %s\n", e.St.Panel.Login, pw)
	case "totp":
		if len(args) > 1 && args[1] == "off" {
			e.St.Panel.TOTP = ""
		} else {
			sec := panel.NewTOTPSecret()
			e.St.Panel.TOTP = sec
			fmt.Println("Добавьте в приложение-аутентификатор:", panel.TOTPURI(sec, e.St.Panel.Login))
		}
		return e.St.Save()
	case "url":
		fmt.Printf("ssh -N -L 8899:%s root@%s\nзатем откройте http://127.0.0.1:8899\n", e.St.Panel.Listen, e.St.PublicIP)
	default:
		return fmt.Errorf("panel passwd|totp|url")
	}
	return nil
}

func doctor(e *core.Engine) error {
	fmt.Printf("vpnstack %s, IP %s, вход %s\n", version.Version, e.St.PublicIP, e.St.EdgeMode)
	b, _ := os.ReadFile("/etc/os-release")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			fmt.Println("ОС:", strings.Trim(l[12:], `"`))
		}
	}
	mt, ma := sys.HostMem()
	fmt.Printf("Память: %d МБ, доступно %d МБ\n", mt>>20, ma>>20)
	if !sys.Exists("/sys/fs/cgroup/cgroup.controllers") {
		fmt.Println("[!] нет cgroup v2 — статистика CPU/RAM по сервисам недоступна")
	}
	for _, t := range []string{"nft", "systemctl", "qrencode", "git", "curl"} {
		if !sys.Has(t) {
			fmt.Printf("[!] нет команды %s\n", t)
		}
	}
	tui.Status(e)
	var ls []string
	for _, l := range sys.Listeners() {
		ls = append(ls, fmt.Sprintf("%s/%d %s", l.Proto, l.Port, l.Process))
	}
	sort.Strings(ls)
	fmt.Println("Слушающие сокеты:\n  " + strings.Join(ls, "\n  "))
	return nil
}

const selfUnit = `[Unit]
Description=vpnstack: панель, статистика, обслуживание
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Slice=vpnstack.slice
EnvironmentFile=-/etc/vpnstack/env
ExecStart=/usr/local/bin/vpnstack serve
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

// setup — вызывается install.sh: юнит vpnstack.service и пароль панели.
func setup() error {
	if err := sys.WriteFileAtomic("/etc/systemd/system/vpnstack.slice", []byte(sys.SliceUnit("", "весь стек")), 0o644); err != nil {
		return err
	}
	if err := sys.WriteUnit("vpnstack.service", selfUnit); err != nil {
		return err
	}
	e := open()
	if e.St.PublicIP == "" {
		e.St.PublicIP = sys.PublicIPv4()
	}
	if e.St.Panel.PassHash == "" {
		pw := sys.RandHex(8)
		h, _ := panel.HashPassword(pw)
		e.St.Panel.PassHash = h
		fmt.Printf("Пароль панели (логин %s): %s\n", e.St.Panel.Login, pw)
	}
	if err := e.St.Save(); err != nil {
		return err
	}
	_ = sys.Systemctl("enable", "vpnstack.service")
	return sys.Systemctl("restart", "vpnstack.service")
}

// serve — фоновый сервис: панель, сбор статистики, сертификаты, OTA.
func serve() error {
	sys.Log = os.Stderr
	e := open()
	store := stats.Load()
	col := &stats.Collector{Store: store, Env: e.Env, St: e.St, Guard: e.TryRun}
	stop := make(chan struct{})
	go col.Run(stop)
	p := panel.New(e, store)
	go func() {
		if err := p.Run(e.St.Panel.Listen); err != nil {
			fmt.Fprintln(os.Stderr, "панель:", err)
			os.Exit(1)
		}
	}()
	// Подтверждение OTA: процесс прожил минуту — обновление удачное.
	go func() {
		time.Sleep(time.Minute)
		ota.Confirm()
	}()
	go func() {
		for {
			e.Tick()
			time.Sleep(10 * time.Minute)
		}
	}()
	go func() {
		time.Sleep(2 * time.Minute)
		for {
			if in, err := ota.Check(e.St.OTA.Channel); err == nil {
				p.SetOTAInfo(in)
				if in.Available && e.St.OTA.Auto {
					if _, err := ota.Apply(e.St.OTA.Channel, ""); err == nil {
						ota.RestartServices()
					} else {
						fmt.Fprintln(os.Stderr, "OTA:", err)
					}
				}
			}
			time.Sleep(6 * time.Hour)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	close(stop)
	time.Sleep(500 * time.Millisecond)
	return store.Save()
}
