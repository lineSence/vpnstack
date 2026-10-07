// Package state хранит конфигурацию стека в /etc/vpnstack/stack.json.
package state

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/lineSence/vpnstack/internal/sys"
)

// Path — файл состояния.
var Path = "/etc/vpnstack/stack.json"

// Stack — всё состояние оркестратора.
type Stack struct {
	SchemaVersion int                 `json:"schema_version"`
	PublicIP      string              `json:"public_ip"`
	ExtraIPs      []string            `json:"extra_ips,omitempty"`
	Email         string              `json:"email"`
	EdgeMode      string              `json:"edge_mode"` // sni — общий вход на TCP 443; ports — отдельные порты
	Channel       string              `json:"channel"`   // stable | prerelease — канал версий сервисов
	Panel         Panel               `json:"panel"`
	OTA           OTA                 `json:"ota"`
	Services      map[string]*Service `json:"services"`
	Meta          map[string]string   `json:"meta,omitempty"`
	mu            sync.Mutex
}

// Panel — настройки веб-панели.
type Panel struct {
	Listen   string `json:"listen"` // только loopback: доступ через SSH-туннель
	Login    string `json:"login"`
	PassHash string `json:"pass_hash"`
	TOTP     string `json:"totp_secret,omitempty"`
}

// OTA — настройки самообновления оркестратора.
type OTA struct {
	Auto    bool   `json:"auto"`
	Channel string `json:"channel"` // stable | prerelease
	Checked string `json:"checked,omitempty"`
	Latest  string `json:"latest,omitempty"`
}

// Service — состояние одного сервиса.
type Service struct {
	Enabled     bool              `json:"enabled"`
	Installed   bool              `json:"installed"`
	Version     string            `json:"version,omitempty"`
	Params      map[string]string `json:"params"`
	Secrets     map[string]string `json:"secrets,omitempty"`
	Users       []*User           `json:"users,omitempty"`
	InstalledAt time.Time         `json:"installed_at,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// User — пользователь (клиент) сервиса.
type User struct {
	Name    string            `json:"name"`
	Created time.Time         `json:"created"`
	Data    map[string]string `json:"data"` // uuid, password, ключи и т. п.
	Note    string            `json:"note,omitempty"`
}

// P возвращает параметр сервиса.
func (s *Service) P(key string) string { return s.Params[key] }

// Set задаёт параметр, если он ещё не задан.
func (s *Service) Default(key, val string) {
	if s.Params == nil {
		s.Params = map[string]string{}
	}
	if s.Params[key] == "" {
		s.Params[key] = val
	}
}

// Secret возвращает секрет, создавая его генератором при отсутствии.
func (s *Service) Secret(key string, gen func() string) string {
	if s.Secrets == nil {
		s.Secrets = map[string]string{}
	}
	if s.Secrets[key] == "" {
		s.Secrets[key] = gen()
	}
	return s.Secrets[key]
}

// FindUser ищет пользователя по имени.
func (s *Service) FindUser(name string) *User {
	for _, u := range s.Users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

// RemoveUser удаляет пользователя.
func (s *Service) RemoveUser(name string) bool {
	for i, u := range s.Users {
		if u.Name == name {
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
			return true
		}
	}
	return false
}

// New — пустое состояние со значениями по умолчанию.
func New() *Stack {
	return &Stack{
		SchemaVersion: 1,
		EdgeMode:      "sni",
		Channel:       "stable",
		Panel:         Panel{Listen: "127.0.0.1:8899", Login: "admin"},
		OTA:           OTA{Channel: "stable"},
		Services:      map[string]*Service{},
	}
}

// Load читает состояние; отсутствующий файл — новое состояние.
func Load() (*Stack, error) {
	b, err := os.ReadFile(Path)
	if os.IsNotExist(err) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	st := New()
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	if st.Services == nil {
		st.Services = map[string]*Service{}
	}
	return st, nil
}

// Save атомарно сохраняет состояние (права 0600 — внутри секреты).
func (st *Stack) Save() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	_ = sys.Backup(Path)
	return sys.WriteFileAtomic(Path, b, 0o600)
}

// Svc возвращает состояние сервиса, создавая его при необходимости.
func (st *Stack) Svc(id string) *Service {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.Services[id]
	if s == nil {
		s = &Service{Params: map[string]string{}}
		st.Services[id] = s
	}
	if s.Params == nil {
		s.Params = map[string]string{}
	}
	return s
}

// EnabledIDs — включённые сервисы в стабильном порядке.
func (st *Stack) EnabledIDs() []string {
	var ids []string
	for id, s := range st.Services {
		if s.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
