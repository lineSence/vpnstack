// Package tui — интерактивный установщик и меню в терминале.
package tui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lineSence/vpnstack/internal/core"
	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/ota"
	"github.com/lineSence/vpnstack/internal/panel"
	"github.com/lineSence/vpnstack/internal/sys"
	"github.com/lineSence/vpnstack/internal/version"
)

var in = bufio.NewReader(os.Stdin)

const (
	cB = "\033[1m"
	cG = "\033[32m"
	cY = "\033[33m"
	cR = "\033[31m"
	cN = "\033[0m"
)

func ask(q, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", q, def)
	} else {
		fmt.Printf("%s: ", q)
	}
	l, _ := in.ReadString('\n')
	l = strings.TrimSpace(l)
	if l == "" {
		return def
	}
	return l
}

func yes(q string, def bool) bool {
	d := "Y/n"
	if !def {
		d = "y/N"
	}
	a := strings.ToLower(ask(q+" ("+d+")", ""))
	if a == "" {
		return def
	}
	return a == "y" || a == "yes" || a == "д" || a == "да"
}

func info(f string, a ...any) { fmt.Printf(cG+"[+] "+cN+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Printf(cY+"[!] "+cN+f+"\n", a...) }
func bad(f string, a ...any)  { fmt.Printf(cR+"[x] "+cN+f+"\n", a...) }
func head(s string)           { fmt.Printf("\n"+cB+"=== %s ==="+cN+"\n", s) }

// Run — главное меню.
func Run(e *core.Engine) error {
	fmt.Printf(cB+"vpnstack %s"+cN+" — VPN/прокси-стек на одном сервере\n", version.Version)
	if err := firstRun(e); err != nil {
		return err
	}
	for {
		head("Меню")
		fmt.Println(" 1) Установить / добавить сервисы")
		fmt.Println(" 2) Состояние")
		fmt.Println(" 3) Пользователи и ссылки")
		fmt.Println(" 4) Изменить настройки сервиса")
		fmt.Println(" 5) Обновления (сервисы и vpnstack)")
		fmt.Println(" 6) Удалить сервис")
		fmt.Println(" 7) Панель управления")
		fmt.Println(" 8) Общие настройки")
		fmt.Println(" 0) Выход")
		switch ask("Выбор", "") {
		case "1":
			Wizard(e)
		case "2":
			Status(e)
		case "3":
			users(e)
		case "4":
			reconfigure(e)
		case "5":
			updates(e)
		case "6":
			remove(e)
		case "7":
			panelMenu(e)
		case "8":
			settings(e)
		case "0", "q", "":
			return nil
		}
	}
}

func firstRun(e *core.Engine) error {
	st := e.St
	if st.PublicIP != "" && st.Email != "" {
		return nil
	}
	head("Первичная настройка")
	ip := st.PublicIP
	if ip == "" {
		ip = sys.PublicIPv4()
	}
	st.PublicIP = ask("Публичный IPv4 сервера", ip)
	st.Email = ask("E-mail для сертификатов Let's Encrypt", st.Email)
	fmt.Println("Режим входа TCP 443:\n 1) общий вход по SNI — все TCP-сервисы на 443 (рекомендуется)\n 2) отдельные порты")
	if ask("Выбор", "1") == "2" {
		st.EdgeMode = "ports"
	} else {
		st.EdgeMode = "sni"
	}
	if st.Panel.PassHash == "" {
		pw := sys.RandHex(8)
		h, _ := panel.HashPassword(pw)
		st.Panel.PassHash = h
		info("Пароль панели (логин %s): %s%s%s — сохраните его", st.Panel.Login, cB, pw, cN)
	}
	return st.Save()
}

func pickModules(e *core.Engine, onlyInstalled bool) []module.Module {
	var list []module.Module
	for _, m := range module.All() {
		if m.Core() {
			continue
		}
		s := e.St.Svc(m.ID())
		if onlyInstalled && !s.Installed {
			continue
		}
		list = append(list, m)
	}
	for i, m := range list {
		mark := ""
		if e.St.Svc(m.ID()).Installed {
			mark = cG + " (установлен)" + cN
		}
		fmt.Printf(" %d) %s%s — %s\n", i+1, m.Title(), mark, m.Description())
	}
	var out []module.Module
	for _, f := range strings.Fields(strings.ReplaceAll(ask("Номера через пробел", ""), ",", " ")) {
		if n, err := strconv.Atoi(f); err == nil && n >= 1 && n <= len(list) {
			out = append(out, list[n-1])
		}
	}
	return out
}

func pickOne(e *core.Engine, filter func(module.Module) bool) module.Module {
	var list []module.Module
	for _, m := range module.All() {
		if !m.Core() && e.St.Svc(m.ID()).Installed && filter(m) {
			list = append(list, m)
		}
	}
	if len(list) == 0 {
		warn("Нет подходящих установленных сервисов")
		return nil
	}
	for i, m := range list {
		fmt.Printf(" %d) %s\n", i+1, m.Title())
	}
	n, _ := strconv.Atoi(ask("Сервис", "1"))
	if n < 1 || n > len(list) {
		return nil
	}
	return list[n-1]
}

// askParams спрашивает параметры: auto — только обязательные и домены.
func askParams(e *core.Engine, m module.Module, manual bool) map[string]string {
	s := e.St.Svc(m.ID())
	params := map[string]string{}
	for _, p := range m.Params() {
		if p.Advanced || !(p.Required || p.Type == module.TDomain) {
			continue
		}
		if p.Help != "" {
			fmt.Printf("  %s\n", p.Help)
		}
		v := ask("  "+p.Label, s.P(p.Key))
		if p.Type == module.TDomain && v != "" {
			if ok, ips := sys.DNSPointsHere(v, e.St.PublicIP); ok {
				info("%s указывает на этот сервер", v)
			} else if m.ID() != "xray" {
				warn("%s → %v, а сервер %s (для своего домена нужна A-запись на сервер)", v, ips, e.St.PublicIP)
			}
		}
		params[p.Key] = v
	}
	if _, err := e.Prepare(m.ID(), params); err != nil {
		bad("%v", err)
		return nil
	}
	if manual {
		for _, p := range m.Params() {
			if _, done := params[p.Key]; done {
				continue
			}
			label := "  " + p.Label
			if p.Options != nil {
				label += " (" + strings.Join(p.Options, "/") + ")"
			}
			params[p.Key] = ask(label, s.P(p.Key))
		}
	}
	return params
}

// Wizard — установка выбранных сервисов.
func Wizard(e *core.Engine) {
	head("Выбор сервисов")
	mods := pickModules(e, false)
	if len(mods) == 0 {
		return
	}
	fmt.Println("Режим:\n 1) автоматически — спрошу только домены, остальное подберу\n 2) вручную — все параметры")
	manual := ask("Выбор", "1") == "2"
	todo := map[string]map[string]string{}
	for _, m := range mods {
		head(m.Title())
		p := askParams(e, m, manual)
		if p == nil {
			continue
		}
		todo[m.ID()] = p
	}
	if len(todo) == 0 {
		return
	}
	for {
		r := e.Plan()
		head("Проверка совместимости")
		if len(r.Problems) == 0 {
			info("Конфликтов нет")
		}
		retry := false
		for _, p := range r.Problems {
			if p.Fatal {
				bad("%s", p.Msg)
			} else {
				warn("%s", p.Msg)
			}
			if p.Kind == "port_busy" && strings.HasSuffix(p.Unit, ".service") && !strings.HasPrefix(p.Unit, "ssh") {
				if yes(fmt.Sprintf("  Остановить и отключить %s?", p.Unit), false) {
					if err := sys.Systemctl("disable", "--now", p.Unit); err != nil {
						bad("%v", err)
					}
					retry = true
				}
			}
		}
		if retry {
			continue
		}
		for _, rt := range r.Routes {
			fmt.Printf("  443/SNI %-9s %v -> %s\n", rt.Name, rt.SNI, rt.Backend)
		}
		if r.Fatal() {
			bad("Есть блокирующие проблемы — измените параметры (меню 4) или освободите порты и повторите")
			for id := range todo {
				if !e.St.Svc(id).Installed {
					e.St.Svc(id).Enabled = false
				}
			}
			return
		}
		break
	}
	if !yes("Устанавливать?", true) {
		return
	}
	sys.Log = os.Stdout
	for _, m := range mods {
		p, ok := todo[m.ID()]
		if !ok {
			continue
		}
		head("Установка: " + m.Title())
		if err := e.Install(m.ID(), p); err != nil {
			bad("%s: %v", m.Title(), err)
			continue
		}
		info("%s установлен", m.Title())
		showFirst(e, m)
	}
	panelHint(e)
}

func showFirst(e *core.Engine, m module.Module) {
	s := e.St.Svc(m.ID())
	name := ""
	if len(s.Users) > 0 {
		name = s.Users[0].Name
	}
	arts, err := e.Artifacts(m.ID(), name)
	if err != nil {
		warn("%v", err)
		return
	}
	printArtifacts(arts)
}

func printArtifacts(arts []module.Artifact) {
	for _, a := range arts {
		fmt.Printf("\n%s%s%s\n%s\n", cB, a.Title, cN, a.Value)
		if a.QR && sys.Has("qrencode") && len(a.Value) < 2000 {
			c := exec.Command("qrencode", "-t", "ANSIUTF8", "-m", "1")
			c.Stdin = strings.NewReader(a.Value)
			c.Stdout = os.Stdout
			_ = c.Run()
		}
	}
}

// Status — состояние сервисов.
func Status(e *core.Engine) {
	head("Состояние")
	for _, s := range e.Services() {
		if !s.Installed {
			continue
		}
		col := cG
		if s.Status.State != "running" {
			col = cR
		}
		fmt.Printf(" %-24s %s%-9s%s %s %s\n", s.Title, col, s.Status.State, cN, s.Version, s.Status.Detail)
		if s.Error != "" {
			fmt.Printf("   ошибка: %s\n", s.Error)
		}
	}
	r := e.Plan()
	for _, p := range r.Problems {
		warn("%s", p.Msg)
	}
}

func users(e *core.Engine) {
	m := pickOne(e, func(m module.Module) bool {
		_, u := m.(module.UserManager)
		_, l := m.(module.Linker)
		if x, ok := m.(*module.External); ok {
			u = x.M.Users
		}
		return u || l
	})
	if m == nil {
		return
	}
	if _, ok := m.(module.UserManager); !ok {
		showFirst(e, m)
		return
	}
	for {
		s := e.St.Svc(m.ID())
		head("Пользователи: " + m.Title())
		for i, u := range s.Users {
			fmt.Printf(" %d) %s\n", i+1, u.Name)
		}
		fmt.Println(" a) добавить   d) удалить   номер — показать подключение   0) назад")
		c := ask("Выбор", "0")
		switch {
		case c == "0":
			return
		case c == "a":
			sys.Log = os.Stdout
			u, err := e.AddUser(m.ID(), ask("Имя", ""), nil)
			if err != nil {
				bad("%v", err)
				continue
			}
			arts, _ := e.Artifacts(m.ID(), u.Name)
			printArtifacts(arts)
		case c == "d":
			if err := e.DelUser(m.ID(), ask("Имя", "")); err != nil {
				bad("%v", err)
			}
		default:
			if n, err := strconv.Atoi(c); err == nil && n >= 1 && n <= len(s.Users) {
				arts, err := e.Artifacts(m.ID(), s.Users[n-1].Name)
				if err != nil {
					bad("%v", err)
				}
				printArtifacts(arts)
			}
		}
	}
}

func reconfigure(e *core.Engine) {
	m := pickOne(e, func(module.Module) bool { return true })
	if m == nil {
		return
	}
	s := e.St.Svc(m.ID())
	params := map[string]string{}
	fmt.Println("Enter — оставить как есть.")
	for _, p := range m.Params() {
		label := "  " + p.Label
		if p.Restart {
			label += " (перезапуск)"
		}
		if v := ask(label, s.P(p.Key)); v != s.P(p.Key) {
			params[p.Key] = v
		}
	}
	if len(params) == 0 {
		return
	}
	sys.Log = os.Stdout
	if err := e.Reconfigure(m.ID(), params); err != nil {
		bad("%v", err)
		return
	}
	info("Применено")
}

func updates(e *core.Engine) {
	head("Обновления")
	sys.Log = os.Stdout
	latest := e.LatestVersions()
	var ids []string
	for _, s := range e.Services() {
		if !s.Installed {
			continue
		}
		l := latest[s.ID]
		mark := ""
		if l != "" && l != s.Version {
			mark = cY + " → " + l + cN
			ids = append(ids, s.ID)
		}
		fmt.Printf(" %-24s %s%s\n", s.Title, s.Version, mark)
	}
	if len(ids) > 0 && yes("Обновить отмеченные сервисы?", true) {
		for _, id := range ids {
			if err := e.Update(id); err != nil {
				bad("%s: %v", id, err)
			}
		}
	}
	oi, err := ota.Check(e.St.OTA.Channel)
	if err != nil {
		warn("Проверка обновлений vpnstack: %v", err)
		return
	}
	if oi.Available && yes(fmt.Sprintf("Доступен vpnstack %s (сейчас %s). Обновить?", oi.Latest, oi.Current), true) {
		if _, err := ota.Apply(e.St.OTA.Channel, ""); err != nil {
			bad("%v", err)
			return
		}
		ota.RestartServices()
		info("vpnstack обновлён — перезапустите меню")
		os.Exit(0)
	} else if !oi.Available {
		info("vpnstack актуален (%s)", oi.Current)
	}
}

func remove(e *core.Engine) {
	m := pickOne(e, func(module.Module) bool { return true })
	if m == nil || !yes("Удалить "+m.Title()+"?", false) {
		return
	}
	purge := yes("Удалить также данные, пользователей и настройки?", false)
	sys.Log = os.Stdout
	if err := e.Remove(m.ID(), purge); err != nil {
		bad("%v", err)
	}
}

func panelHint(e *core.Engine) {
	head("Панель управления")
	fmt.Printf("Панель слушает только %s. С вашего компьютера:\n  ssh -N -L 8899:%s root@%s\nи откройте http://127.0.0.1:8899 (логин %s)\n",
		e.St.Panel.Listen, e.St.Panel.Listen, e.St.PublicIP, e.St.Panel.Login)
}

func panelMenu(e *core.Engine) {
	panelHint(e)
	fmt.Println(" 1) сменить пароль   2) включить/выключить 2FA (TOTP)   0) назад")
	switch ask("Выбор", "0") {
	case "1":
		pw := ask("Новый пароль (пусто — сгенерировать)", "")
		if pw == "" {
			pw = sys.RandHex(8)
		}
		h, _ := panel.HashPassword(pw)
		e.St.Panel.PassHash = h
		_ = e.St.Save()
		info("Пароль: %s", pw)
	case "2":
		if e.St.Panel.TOTP != "" {
			e.St.Panel.TOTP = ""
			info("2FA выключена")
		} else {
			sec := panel.NewTOTPSecret()
			uri := panel.TOTPURI(sec, e.St.Panel.Login)
			printArtifacts([]module.Artifact{{Title: "Добавьте в приложение-аутентификатор", Value: uri, QR: true}})
			if !panel.CheckTOTP(sec, ask("Код из приложения", "")) {
				bad("Код не подошёл — 2FA не включена")
				return
			}
			e.St.Panel.TOTP = sec
			info("2FA включена")
		}
		_ = e.St.Save()
	}
}

func settings(e *core.Engine) {
	st := e.St
	head("Общие настройки")
	ip := ask("Публичный IPv4", st.PublicIP)
	email := ask("E-mail ACME", st.Email)
	mode := ask("Вход TCP 443: sni (общий) / ports (отдельные порты)", st.EdgeMode)
	ch := ask("Канал версий сервисов: stable / prerelease", st.Channel)
	auto := yes("Автообновление vpnstack (OTA)?", st.OTA.Auto)
	changed := ip != st.PublicIP || email != st.Email || mode != st.EdgeMode
	st.PublicIP, st.Email, st.Channel, st.OTA.Auto = ip, email, ch, auto
	if mode == "sni" || mode == "ports" {
		st.EdgeMode = mode
	}
	_ = st.Save()
	if changed && yes("Применить ко всем сервисам сейчас?", true) {
		sys.Log = os.Stdout
		if err := e.ApplyAll(); err != nil {
			bad("%v", err)
		}
	}
}
