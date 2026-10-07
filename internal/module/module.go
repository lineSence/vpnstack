// Package module описывает контракт сервиса (модуля) оркестратора.
//
// Каждый сервис — FPTN, Xray, Hysteria и т. д. — реализует Module. Необязательные
// возможности (пользователи, статистика трафика, сайты Caddy, правила nftables)
// подключаются дополнительными интерфейсами. Сторонние сервисы добавляются без
// пересборки через манифест в /etc/vpnstack/modules.d (см. external.go).
package module

import (
	"github.com/lineSence/vpnstack/internal/state"
)

// ParamType — тип параметра для форм TUI и панели.
type ParamType string

const (
	TString ParamType = "string"
	TInt    ParamType = "int"
	TBool   ParamType = "bool"
	TSelect ParamType = "select"
	TDomain ParamType = "domain"
	TPort   ParamType = "port"
	TList   ParamType = "list" // значения через запятую
	TSecret ParamType = "secret"
)

// Param — настраиваемый параметр сервиса.
type Param struct {
	Key      string    `json:"key"`
	Label    string    `json:"label"`
	Help     string    `json:"help,omitempty"`
	Type     ParamType `json:"type"`
	Options  []string  `json:"options,omitempty"`
	Required bool      `json:"required,omitempty"`
	Advanced bool      `json:"advanced,omitempty"` // показывается только в ручном режиме
	Restart  bool      `json:"restart,omitempty"`  // изменение требует переустановки/перезапуска
}

// EdgeRoute — маршрут общего входа TCP 443 по SNI.
type EdgeRoute struct {
	Name          string   `json:"name,omitempty"` // заполняет оркестратор (id сервиса)
	SNI           []string `json:"sni"`            // домены (поддомены совпадают тоже)
	Backend       string   `json:"backend"`        // 127.0.0.1:port
	ProxyProtocol bool     `json:"proxy_protocol"` // передавать PROXY v2 (реальный IP клиента)
	Default       bool     `json:"default"`        // получать соединения с неизвестным SNI
	Priority      int      `json:"priority"`       // больше — раньше при совпадении
}

// Need — потребность сервиса в порте.
type Need struct {
	Proto   string     `json:"proto"`           // tcp | udp
	Port    int        `json:"port"`            // 0 — подобрать автоматически
	Public  bool       `json:"public"`          // слушает внешний интерфейс
	Purpose string     `json:"purpose"`         // для сообщений о конфликтах
	Param   string     `json:"param,omitempty"` // параметр, куда записать выбранный порт
	Edge    *EdgeRoute `json:"edge,omitempty"`  // публичный TCP 443 через общий вход
}

// Status — состояние сервиса.
type Status struct {
	State   string            `json:"state"` // running | stopped | failed | not_installed | partial
	Units   map[string]string `json:"units"`
	Version string            `json:"version,omitempty"`
	Detail  string            `json:"detail,omitempty"`
}

// Traffic — счётчики трафика (байты).
type Traffic struct {
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// Artifact — то, что выдаётся пользователю: ссылка, файл конфигурации, токен.
type Artifact struct {
	Kind  string `json:"kind"` // uri | file | token | text
	Title string `json:"title"`
	Value string `json:"value"`
	Name  string `json:"name,omitempty"` // имя файла для kind=file
	QR    bool   `json:"qr"`
}

// Env — окружение, доступное модулю.
type Env struct {
	Stack *state.Stack
	// Host — адрес для клиентских ссылок: домен сервиса или публичный IP.
	Host func(svc *state.Service) string
	// EdgePort — внешний TCP-порт общего входа (443).
	EdgePort int
	// EdgeEnabled — работает ли режим общего входа по SNI.
	EdgeEnabled bool
	// GoBinary — путь к Go (ставится по требованию, нужен для сборки из исходников).
	GoBinary func() (string, error)
	// CaddyCert возвращает пути к сертификату и ключу, выпущенным Caddy для домена.
	CaddyCert func(domain string) (cert, key string, ok bool)
	// Sites — сайты Caddy всех включённых сервисов (для модуля caddy).
	Sites func() []CaddySite
	// Routes — маршруты общего входа всех включённых сервисов (для модуля edge).
	Routes func() []EdgeRoute
	// Self — путь к исполняемому файлу vpnstack.
	Self string
}

// Module — обязательный контракт сервиса.
type Module interface {
	ID() string
	Title() string
	Description() string
	Params() []Param
	// Core — служебный модуль (Caddy, edge): включается автоматически, если нужен.
	Core() bool
	// AutoDefaults заполняет незаданные параметры и секреты автоматически.
	AutoDefaults(env *Env, s *state.Service) error
	// Needs — порты и маршруты, нужные сервису с текущими параметрами.
	Needs(env *Env, s *state.Service) []Need
	// Install скачивает и ставит программу, пишет конфигурацию и запускает.
	Install(env *Env, s *state.Service) error
	// Apply перегенерирует конфигурацию из состояния и применяет её.
	Apply(env *Env, s *state.Service) error
	// Remove останавливает и удаляет сервис. purge — удалить и данные.
	Remove(env *Env, s *state.Service, purge bool) error
	// Units — systemd-юниты сервиса (для статуса, перезапуска, cgroup).
	Units(s *state.Service) []string
	Status(env *Env, s *state.Service) Status
	// Latest — последняя доступная версия в выбранном канале.
	Latest(env *Env) (string, error)
	// Update ставит последнюю версию, сохраняя конфигурацию и пользователей.
	Update(env *Env, s *state.Service) error
}

// UserManager — сервис с пользователями.
type UserManager interface {
	AddUser(env *Env, s *state.Service, name string, opts map[string]string) (*state.User, error)
	DelUser(env *Env, s *state.Service, name string) error
	Artifacts(env *Env, s *state.Service, u *state.User) ([]Artifact, error)
}

// TrafficReporter — сервис отдаёт трафик по пользователям (накопительные счётчики).
type TrafficReporter interface {
	UserTraffic(env *Env, s *state.Service) (map[string]Traffic, error)
}

// CaddySite — сайт, который должен обслуживать Caddy (сертификат, прокси и т. п.).
type CaddySite struct {
	Host  string // домен
	Block string // содержимое блока Caddyfile (без заголовка)
	Order int
}

// CaddyConsumer — сервис, которому нужен сайт/сертификат в Caddy.
type CaddyConsumer interface {
	CaddySites(env *Env, s *state.Service) []CaddySite
}

// NFTProvider — сервис добавляет правила nftables (NAT и т. п.) в общую таблицу.
type NFTProvider interface {
	NFT(env *Env, s *state.Service) string
}

// Sysctls — сервису нужны параметры ядра.
type Sysctls interface {
	Sysctls() map[string]string
}

// Linker — сервис без пользователей, но с общей ссылкой/данными подключения.
type Linker interface {
	Links(env *Env, s *state.Service) ([]Artifact, error)
}

// Configurer — сервис умеет показывать свои конфигурационные файлы (для панели).
type Configurer interface {
	ConfigFiles(s *state.Service) []string
}

// Ticker — сервису нужны периодические действия (продление сертификата и т. п.).
type Ticker interface {
	Tick(env *Env, s *state.Service)
}
