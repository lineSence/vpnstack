package modules

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// HyAuthPath — команда авторизации Hysteria (`auth.type: command`). Это ссылка на сам
// vpnstack: по имени vpnstack-hy-auth он сразу проверяет логин и завершается.
var HyAuthPath = "/usr/local/lib/vpnstack/vpnstack-hy-auth"

// HyAuthName — имя, по которому vpnstack узнаёт, что вызван как команда авторизации.
const HyAuthName = "vpnstack-hy-auth"

type hyAuthUser struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
}

type hyAuthFile struct {
	// Users — логин в нижнем регистре → пользователь (клиент передаёт "логин:пароль").
	Users map[string]hyAuthUser `json:"users"`
	// Shared — общие пароли перенятой установки (auth.type: password): пароль → id.
	Shared map[string]string `json:"shared,omitempty"`
}

func (h *Hysteria) authPath() string { return filepath.Join(h.cfgDir(), "auth.json") }

// writeAuth атомарно пишет файл пользователей; Hysteria подхватывает его при следующем
// подключении (перезапуск не нужен).
func (h *Hysteria) writeAuth(s *state.Service) error {
	f := hyAuthFile{Users: map[string]hyAuthUser{}, Shared: map[string]string{}}
	for _, u := range s.Users {
		if u.Data["legacy"] == "1" {
			f.Shared[u.Data["password"]] = u.Name
			continue
		}
		f.Users[strings.ToLower(hyLogin(u))] = hyAuthUser{Name: u.Name, Pass: u.Data["password"]}
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := ensureHyAuthLink(); err != nil {
		return err
	}
	if err := sys.WriteFileAtomic(h.authPath(), b, 0o640); err != nil {
		return err
	}
	_, _ = sys.Run("chgrp", "hysteria", h.authPath())
	return nil
}

// ensureHyAuthLink создаёт ссылку vpnstack-hy-auth → vpnstack.
func ensureHyAuthLink() error {
	self := "/usr/local/bin/vpnstack"
	if exe, err := os.Executable(); err == nil && !strings.HasPrefix(exe, "/tmp/") {
		self = exe
	}
	if cur, err := os.Readlink(HyAuthPath); err == nil && cur == self {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(HyAuthPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(HyAuthPath)
	return os.Symlink(self, HyAuthPath)
}

// HyAuthCheck — проверка строки авторизации; возвращает id пользователя.
func HyAuthCheck(path, auth string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var f hyAuthFile
	if json.Unmarshal(b, &f) != nil {
		return "", false
	}
	if user, pass, ok := strings.Cut(auth, ":"); ok {
		if want, ok := f.Users[strings.ToLower(user)]; ok && want.Pass != "" &&
			subtle.ConstantTimeCompare([]byte(want.Pass), []byte(pass)) == 1 {
			return want.Name, true
		}
	}
	for pw, id := range f.Shared {
		if pw != "" && subtle.ConstantTimeCompare([]byte(pw), []byte(auth)) == 1 {
			return id, true
		}
	}
	return "", false
}

// HyAuthMain — точка входа команды авторизации: hysteria передаёт addr, auth, tx.
func HyAuthMain(args []string) int {
	if len(args) < 2 {
		return 2
	}
	id, ok := HyAuthCheck(filepath.Join(EtcDir, "hysteria", "auth.json"), args[1])
	if !ok {
		return 1
	}
	fmt.Println(id)
	return 0
}

// hyLogin — логин клиента: перенятый (как в старом конфиге) или имя пользователя.
func hyLogin(u *state.User) string { return firstNonEmpty(u.Data["login"], u.Name) }
