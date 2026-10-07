// Package modules — встроенные сервисы vpnstack.
package modules

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/module"
	"github.com/lineSence/vpnstack/internal/state"
	"github.com/lineSence/vpnstack/internal/sys"
)

// Пути установки (переменные — для тестов).
var (
	BinDir  = "/opt/vpnstack/bin"
	EtcDir  = "/etc/vpnstack"
	DataDir = "/var/lib/vpnstack"
)

// base — общие поля модулей.
type base struct {
	id, title, desc string
	order           int
	units           []string
}

func (b *base) ID() string                          { return b.id }
func (b *base) Title() string                       { return b.title }
func (b *base) Description() string                 { return b.desc }
func (b *base) Core() bool                          { return false }
func (b *base) Order() int                          { return b.order }
func (b *base) Units(*state.Service) []string       { return b.units }
func (b *base) cfgDir() string                      { return filepath.Join(EtcDir, b.id) }
func (b *base) dataDir() string                     { return filepath.Join(DataDir, b.id) }
func (b *base) ConfigFiles(*state.Service) []string { return nil }

// unitsStatus — статус по набору systemd-юнитов.
func unitsStatus(s *state.Service, units []string) module.Status {
	st := module.Status{Units: map[string]string{}, Version: s.Version}
	if !s.Installed {
		st.State = "not_installed"
		return st
	}
	running, failed := 0, 0
	for _, u := range units {
		v := sys.UnitState(u)
		st.Units[u] = v
		switch v {
		case "active":
			running++
		case "failed":
			failed++
		}
	}
	switch {
	case running == len(units):
		st.State = "running"
	case failed > 0:
		st.State = "failed"
	case running == 0:
		st.State = "stopped"
	default:
		st.State = "partial"
	}
	return st
}

// serviceUnit — systemd-юнит процесса сервиса в его slice.
func serviceUnit(id, desc, execStart string, extra string) string {
	return fmt.Sprintf(`[Unit]
Description=vpnstack: %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Slice=%s
ExecStart=%s
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
%s
[Install]
WantedBy=multi-user.target
`, desc, sys.SliceName(id), execStart, extra)
}

// installUnit пишет slice и юнит, включает и (пере)запускает.
func installUnit(id, title, unit, content string) error {
	if err := sys.EnsureSlice(id, title); err != nil {
		return err
	}
	if err := sys.WriteUnit(unit, content); err != nil {
		return err
	}
	if err := sys.Systemctl("enable", unit); err != nil {
		return err
	}
	return sys.Systemctl("restart", unit)
}

// removeUnits останавливает и удаляет юниты и slice.
func removeUnits(id string, units ...string) {
	for _, u := range units {
		_ = sys.Systemctl("disable", "--now", u)
		sys.RemoveUnit(u)
	}
	sys.RemoveUnit(sys.SliceName(id))
	_ = sys.Systemctl("daemon-reload")
}

// waitActive ждёт, пока юнит станет активным.
func waitActive(unit string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if sys.Active(unit) {
			time.Sleep(time.Second)
			if sys.Active(unit) {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	out, _ := sys.Output("journalctl", "-u", unit, "-n", "30", "--no-pager")
	return fmt.Errorf("%s не запустился:\n%s", unit, out)
}

// latestTag — последний тег релиза в канале стека.
func latestTag(env *module.Env, repo string) (string, error) {
	r, err := sys.LatestRelease(repo, env.Stack.Channel != "prerelease")
	if err != nil {
		return "", err
	}
	return r.Tag, nil
}

// arch — архитектура в терминах большинства релизов.
func arch() string { return runtime.GOARCH }

// randInt — случайное число в [lo, hi].
func randInt(lo, hi int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	return lo + int(n.Int64())
}

func itoa(i int) string { return strconv.Itoa(i) }
func atoi(s string) int { i, _ := strconv.Atoi(strings.TrimSpace(s)); return i }

// boolP — параметр-флаг.
func boolP(s *state.Service, key string) bool {
	v := strings.ToLower(s.P(key))
	return v == "true" || v == "yes" || v == "1" || v == "on"
}

// list — параметр-список через запятую.
func list(s *state.Service, key string) []string {
	var out []string
	for _, v := range strings.Split(s.P(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// x25519 возвращает пару ключей (закрытый, открытый) в сыром виде.
func x25519() (priv, pub []byte) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	priv = k.Bytes()
	// Клэмпинг как у `wg genkey` — ключ совместим со всеми реализациями.
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	k2, _ := ecdh.X25519().NewPrivateKey(priv)
	return priv, k2.PublicKey().Bytes()
}

// wgPub вычисляет открытый ключ WireGuard из закрытого (base64).
func wgPub(privB64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// realityPub вычисляет открытый ключ REALITY (base64url без '=') из закрытого.
func realityPub(privB64 string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// uuid4 — случайный UUID v4.
func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// password — случайный пароль из безопасных для URI символов.
func password(n int) string {
	const abc = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = abc[randInt(0, len(abc)-1)]
	}
	return string(b)
}

// selfSigned создаёт самоподписанный сертификат и возвращает SHA-256 отпечаток (hex).
func selfSigned(certPath, keyPath, cn string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := sys.WriteFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	if err := sys.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// certFingerprint — SHA-256 отпечаток первого сертификата PEM-файла.
func certFingerprint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// copyIfChanged копирует файл, если содержимое отличается. Возвращает true при изменении.
func copyIfChanged(src, dst string, perm os.FileMode) (bool, error) {
	a, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	if b, err := os.ReadFile(dst); err == nil && string(a) == string(b) {
		return false, nil
	}
	return true, sys.WriteFileAtomic(dst, a, perm)
}

// ensureUser создаёт системного пользователя.
func ensureUser(name string) {
	if _, err := sys.Output("id", "-u", name); err == nil {
		return
	}
	_, _ = sys.Run("useradd", "--system", "--home", "/nonexistent", "--shell", "/usr/sbin/nologin", name)
}

// aptInstall ставит пакеты apt.
func aptInstall(pkgs ...string) error {
	if _, err := sys.Run("apt-get", "update"); err != nil {
		return err
	}
	_, err := sys.Run("apt-get", append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)...)
	return err
}

// host — адрес для клиентских ссылок.
func host(env *module.Env, s *state.Service) string {
	if env.Host != nil {
		return env.Host(s)
	}
	if d := s.P("domain"); d != "" {
		return d
	}
	return env.Stack.PublicIP
}

// publicPort — внешний порт: 443 в режиме общего входа или собственный порт.
func publicPort(env *module.Env, s *state.Service, key string) int {
	if env.EdgeEnabled {
		return env.EdgePort
	}
	return atoi(s.P(key))
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

// certValidFor — сертификат в файле подходит для домена и действует ещё не меньше left.
func certValidFor(path, domain string, left time.Duration) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	return c.VerifyHostname(domain) == nil && time.Until(c.NotAfter) > left
}

// legacyNeeds — старые публичные TCP-порты перенятой установки: nftables перенаправляет
// их на общий вход 443, а тот разбирает соединения по SNI как обычно.
func legacyNeeds(s *state.Service, what string) []module.Need {
	var n []module.Need
	for _, p := range list(s, "legacy_tcp") {
		if port := atoi(p); port > 0 && port != 443 {
			n = append(n, module.Need{Proto: "tcp", Port: port, Public: true, Redirect: true,
				Purpose: what + ": старый порт → общий вход 443"})
		}
	}
	return n
}

// EnsureUser — системный пользователь для сервиса (нужен ядру при переносе файлов).
func EnsureUser(name string) { ensureUser(name) }

// CaddyStorageDir — хранилище сертификатов Caddy стека (certmagic).
func CaddyStorageDir() string { return filepath.Join(DataDir, "caddy", "caddy") }

// HysteriaCertPaths — куда модуль hysteria кладёт сертификат и ключ.
func HysteriaCertPaths() (string, string) { return (&Hysteria{base{id: "hysteria"}}).certPaths() }
