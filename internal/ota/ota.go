// Package ota — самообновление vpnstack из релизов GitHub.
//
// Релиз содержит vpnstack-linux-<arch>, SHA256SUMS и SHA256SUMS.sig (подпись
// ed25519 файла сумм). Открытый ключ встраивается при сборке (version.SigningKey).
// Новый бинарник ставится атомарно, старый сохраняется как vpnstack.prev; если
// после перезапуска новая версия не подтвердит работоспособность за 3 минуты,
// таймер systemd запускает старую версию, и она откатывает обновление.
package ota

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/sys"
	"github.com/lineSence/vpnstack/internal/version"
)

// Пути.
var (
	Binary  = "/usr/local/bin/vpnstack"
	Pending = "/var/lib/vpnstack/ota-pending.json"
)

// Info — результат проверки.
type Info struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Published string `json:"published,omitempty"`
}

// Check ищет новую версию в канале stable/prerelease.
func Check(channel string) (Info, error) {
	in := Info{Current: version.Version}
	r, err := sys.LatestRelease(version.Repo, channel != "prerelease")
	if err != nil {
		return in, err
	}
	in.Latest, in.Published = r.Tag, r.Published
	in.Available = Newer(r.Tag, version.Version)
	return in, nil
}

// Newer сравнивает версии вида v1.2.3[-rc.1].
func Newer(a, b string) bool {
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa.n[i] != pb.n[i] {
			return pa.n[i] > pb.n[i]
		}
	}
	if pa.pre == pb.pre {
		return false
	}
	if pa.pre == "" {
		return true // релиз новее пре-релиза
	}
	if pb.pre == "" {
		return false
	}
	return pa.pre > pb.pre
}

type ver struct {
	n   [3]int
	pre string
}

func parse(s string) ver {
	var v ver
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		v.pre, s = s[i+1:], s[:i]
	}
	for i, p := range strings.SplitN(s, ".", 3) {
		v.n[i], _ = strconv.Atoi(p)
	}
	return v
}

type pending struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// Apply скачивает, проверяет подпись и ставит версию tag (пусто — последнюю).
func Apply(channel, tag string) (string, error) {
	var r *sys.Release
	var err error
	if tag == "" {
		r, err = sys.LatestRelease(version.Repo, channel != "prerelease")
	} else {
		r, err = sys.ReleaseByTag(version.Repo, tag)
	}
	if err != nil {
		return "", err
	}
	name := "vpnstack-linux-" + runtime.GOARCH
	bin, ok := r.Find(name)
	sums, ok2 := r.Find("SHA256SUMS")
	if !ok || !ok2 {
		return "", fmt.Errorf("в релизе %s нет %s или SHA256SUMS", r.Tag, name)
	}
	text, err := sys.FetchText(assetURL(sums))
	if err != nil {
		return "", err
	}
	if err := verifySig(r, text); err != nil {
		return "", err
	}
	sum := sys.ChecksumFor(text, name)
	tmp := Binary + ".new"
	if err := sys.DownloadVerified(assetURL(bin), tmp, sum); err != nil {
		return "", err
	}
	_ = os.Chmod(tmp, 0o755)
	out, err := sys.Output(tmp, "version")
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("новый бинарник не запускается: %w", err)
	}
	sys.Logf("Новая версия: %s", strings.TrimSpace(out))
	if err := sys.InstallBinary(tmp, Binary); err != nil {
		return "", err
	}
	p, _ := json.Marshal(pending{From: version.Version, To: r.Tag, At: time.Now()})
	_ = sys.WriteFileAtomic(Pending, p, 0o600)
	// Страховка: через 3 минуты старая версия откатит обновление, если новая не подтвердила работу.
	_, _ = sys.Run("systemd-run", "--unit=vpnstack-ota-guard", "--on-active=180", "--timer-property=AccuracySec=5s",
		Binary+".prev", "ota-guard")
	return r.Tag, nil
}

// assetURL — для приватного репозитория скачиваем через API (нужен токен).
func assetURL(a sys.Asset) string {
	if sys.GitHubToken != "" && a.API != "" {
		return a.API
	}
	return a.URL
}

func verifySig(r *sys.Release, sums string) error {
	if version.SigningKey == "" {
		if os.Getenv("VPNSTACK_OTA_ALLOW_UNSIGNED") == "1" {
			sys.Logf("[!] сборка без ключа подписи — проверяю только SHA256SUMS (VPNSTACK_OTA_ALLOW_UNSIGNED=1)")
			return nil
		}
		return fmt.Errorf("эта сборка без открытого ключа подписи — OTA отключено (VPNSTACK_OTA_ALLOW_UNSIGNED=1 — на свой риск)")
	}
	sa, ok := r.Find("SHA256SUMS.sig")
	if !ok {
		return fmt.Errorf("в релизе %s нет подписи SHA256SUMS.sig", r.Tag)
	}
	sigText, err := sys.FetchText(assetURL(sa))
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigText))
	if err != nil {
		return fmt.Errorf("подпись повреждена: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(version.SigningKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("встроенный ключ подписи некорректен")
	}
	if !ed25519.Verify(pub, []byte(sums), sig) {
		return fmt.Errorf("подпись SHA256SUMS не прошла проверку — обновление отклонено")
	}
	return nil
}

// Confirm — новая версия работает: снять страховку.
func Confirm() {
	if !sys.Exists(Pending) {
		return
	}
	os.Remove(Pending)
	_ = sys.Systemctl("stop", "vpnstack-ota-guard.timer")
	sys.Logf("OTA: версия %s подтверждена", version.Version)
}

// Guard — запускается старой версией по таймеру: откат, если обновление не подтверждено.
func Guard() error {
	b, err := os.ReadFile(Pending)
	if err != nil {
		return nil // подтверждено
	}
	var p pending
	_ = json.Unmarshal(b, &p)
	prev := Binary + ".prev"
	if !sys.Exists(prev) {
		return fmt.Errorf("нет %s для отката", prev)
	}
	bad := Binary + ".failed"
	_ = os.Rename(Binary, bad)
	if err := copyExec(prev, Binary); err != nil {
		_ = os.Rename(bad, Binary)
		return err
	}
	os.Remove(Pending)
	_ = sys.WriteFileAtomic(filepath.Join(filepath.Dir(Pending), "ota-rollback.json"), b, 0o600)
	_ = sys.Systemctl("restart", "vpnstack.service", "vpnstack-edge.service")
	return nil
}

func copyExec(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return sys.WriteFileAtomic(dst, b, 0o755)
}

// RestartServices перезапускает процессы vpnstack после установки нового бинарника.
// Перезапуск отложен через systemd-run, чтобы панель успела ответить и не убила сама себя.
func RestartServices() {
	_, _ = sys.Run("systemd-run", "--unit=vpnstack-ota-restart-"+strconv.FormatInt(time.Now().Unix(), 10), "--on-active=3",
		"/bin/systemctl", "try-restart", "vpnstack-edge.service", "vpnstack.service")
}
