package adopt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lineSence/vpnstack/internal/state"
)

func scanFPTN() []*Found {
	var out []*Found
	for _, c := range dockerPS() {
		if !strings.Contains(c.Image, "fptn-vpn-server") || c.Labels["com.docker.compose.project"] == "vpnstack-fptn" {
			continue
		}
		o := state.Origin{Kind: "docker", Source: "FPTN (контейнер " + c.Name + ")", Containers: []string{c.ID},
			State: state.OriginImported, ImportedAt: time.Now(), Files: map[string]string{}}
		if wd := c.Labels["com.docker.compose.project.working_dir"]; wd != "" {
			o.Source += ", docker compose в " + wd
			o.Configs = append(o.Configs, filepath.Join(wd, "docker-compose.yml"), filepath.Join(wd, ".env"))
		}
		f := newFound("fptn", "FPTN", o)
		importFPTN(f, c)
		out = append(out, f)
	}
	return out
}

// importFPTN берёт настройки из окружения контейнера, а ключи сервера и пользователей —
// из каталога /etc/fptn (он копируется целиком, поэтому выданные токены остаются в силе).
func importFPTN(f *Found, c dockerC) {
	data := c.Mounts["/etc/fptn"]
	if data == "" {
		f.Blocking = append(f.Blocking, "у контейнера нет тома /etc/fptn — ключи сервера и пользователи недоступны")
		return
	}
	f.Origin.Files["fptn_data"] = data
	port := c.Ports["443/tcp"]
	if port == 0 {
		f.Blocking = append(f.Blocking, "порт 443/tcp контейнера не опубликован")
		return
	}
	f.port("tcp", port)
	f.Params["port"] = strconv.Itoa(port)
	if port != 443 {
		f.Params["legacy_tcp"] = strconv.Itoa(port)
	}
	if v := c.Env["ALLOWED_SNI_LIST"]; v != "" {
		f.Params["sni_list"] = v
	} else {
		f.Risky = append(f.Risky, "в старой установке не задан ALLOWED_SNI_LIST (принимался любой SNI); за общим входом FPTN получает только SNI из списка — "+
			"клиенты с другим SNI перестанут подключаться. Задайте список: vpnstack set fptn sni_list=…")
	}
	for env, p := range map[string]string{"MAX_ACTIVE_SESSIONS_PER_USER": "max_sessions", "MTU_SIZE": "mtu",
		"ENABLE_ADS_FILTER": "ads_filter", "ENABLE_TORRENT_FILTER": "torrent_filter", "ENABLE_SPAM_FILTER": "spam_filter",
		"USING_DNS_SERVER": "dns_server", "DNS_IPV4_PRIMARY": "dns4_primary", "DNS_IPV4_SECONDARY": "dns4_secondary",
		"DNS_IPV6_ENABLE": "dns6_enable", "DNS_IPV6_PRIMARY": "dns6_primary", "DNS_IPV6_SECONDARY": "dns6_secondary",
		"ADS_BLOCKLIST_URLS": "ads_blocklist_urls"} {
		if v := c.Env[env]; v != "" {
			f.Params[p] = v
		}
	}
	if c.Env["USE_REMOTE_SERVER_AUTH"] == "true" {
		f.Blocking = append(f.Blocking, "включена удалённая авторизация (USE_REMOTE_SERVER_AUTH) — пользователи хранятся на другом сервере")
	}
	f.Params["_version"] = fptnImageVersion(c, imageRepoDigests(c.ImageID))
	if f.Params["_version"] == "" {
		delete(f.Params, "_version")
		f.Warnings = append(f.Warnings, "не удалось определить точную версию образа "+c.Image+
			" — при переносе будет установлена последняя версия FPTN")
	}
	b, err := os.ReadFile(filepath.Join(data, "users.list"))
	if err != nil {
		f.Warnings = append(f.Warnings, "users.list не прочитан: "+err.Error())
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		fs := strings.Fields(l)
		if len(fs) < 3 {
			continue
		}
		f.addUser(fs[0], map[string]string{"bandwidth": fs[2]})
		if f.Users[len(f.Users)-1].Name != fs[0] {
			f.Warnings = append(f.Warnings, fmt.Sprintf("имя %q в vpnstack: %s (логин в FPTN прежний)", fs[0], f.Users[len(f.Users)-1].Name))
			f.Users[len(f.Users)-1].Data["login"] = fs[0]
		}
	}
	for _, k := range []string{"server.key", "server.crt"} {
		if _, err := os.Stat(filepath.Join(data, k)); err != nil {
			f.Warnings = append(f.Warnings, "нет "+k+" в "+data+" — будет создан новый ключ, клиентам потребуются новые токены")
		}
	}
}

// fptnImageVersion — версия, которую перенос должен сохранить: явный тег образа, а для
// «latest» (или без тега) — точный дайджест локального образа. «latest» на Docker Hub
// мог уйти вперёд, и перенос незаметно обновил бы сервер.
func fptnImageVersion(c dockerC, digests []string) string {
	ref := c.Image
	if _, d, ok := strings.Cut(ref, "@"); ok {
		return "@" + d
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		if tag := ref[i+1:]; tag != "" && tag != "latest" {
			return tag
		}
	}
	for _, d := range digests {
		if name, sum, ok := strings.Cut(d, "@"); ok && strings.HasSuffix(name, "fptn-vpn-server") && strings.HasPrefix(sum, "sha256:") {
			return "@" + sum
		}
	}
	return ""
}

// imageRepoDigests — дайджесты реестра для локального образа.
func imageRepoDigests(id string) []string {
	if id == "" {
		return nil
	}
	out, err := run("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", id)
	if err != nil {
		return nil
	}
	var d []string
	_ = json.Unmarshal([]byte(strings.TrimSpace(out)), &d)
	return d
}
