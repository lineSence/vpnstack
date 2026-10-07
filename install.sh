#!/usr/bin/env bash
# vpnstack — установка одной командой:
#   curl -fsSL https://raw.githubusercontent.com/lineSence/vpnstack/main/install.sh | sudo bash
# Приватный репозиторий: sudo VPNSTACK_GITHUB_TOKEN=github_pat_... bash install.sh
# Переменные: VPNSTACK_VERSION (тег, по умолчанию последний), VPNSTACK_FROM_SOURCE=1 (собрать из исходников),
#             VPNSTACK_PUBLIC_KEY (ed25519, base64 — проверить подпись SHA256SUMS), VPNSTACK_NO_MENU=1.
set -euo pipefail

REPO="${VPNSTACK_REPO:-lineSence/vpnstack}"
VERSION="${VPNSTACK_VERSION:-latest}"
TOKEN="${VPNSTACK_GITHUB_TOKEN:-}"
PUBKEY="${VPNSTACK_PUBLIC_KEY:-}"
BIN=/usr/local/bin/vpnstack

G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'
info() { echo "${G}[+]${N} $*"; }
warn() { echo "${Y}[!]${N} $*" >&2; }
die()  { echo "${R}[x]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Запустите от root: curl -fsSL ... | sudo bash"
command -v systemctl >/dev/null || die "Нужен systemd"
. /etc/os-release 2>/dev/null || true
[[ "${ID:-}" == ubuntu ]] || warn "Проверено на Ubuntu 22.04/24.04/26.04; у вас ${PRETTY_NAME:-неизвестная ОС}"
case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "Архитектура $(uname -m) не поддерживается" ;;
esac
mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
(( mem >= 900 )) || warn "Памяти ${mem} МБ — для нескольких сервисов рекомендуется от 1 ГБ"

info "Пакеты: curl, jq, nftables, qrencode, git"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl jq nftables qrencode git iproute2 tar >/dev/null

auth=()
[[ -n $TOKEN ]] && auth=(-H "Authorization: Bearer $TOKEN")
gh() { curl -fsSL --proto '=https' --tlsv1.2 "${auth[@]}" -H "User-Agent: vpnstack-install" "$@"; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

asset() { # $1 = имя файла → скачать в $tmp
	local id
	id=$(jq -r --arg n "$1" '.assets[] | select(.name == $n) | .id' "$tmp/release.json")
	[[ -n $id && $id != null ]] || return 1
	gh -H "Accept: application/octet-stream" -o "$tmp/$1" "https://api.github.com/repos/$REPO/releases/assets/$id"
}

from_release() {
	local url="https://api.github.com/repos/$REPO/releases/latest"
	[[ $VERSION != latest ]] && url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
	gh -o "$tmp/release.json" "$url" 2>/dev/null || return 1
	local tag; tag=$(jq -r .tag_name "$tmp/release.json")
	info "Релиз $tag"
	asset "vpnstack-linux-$ARCH" && asset SHA256SUMS || return 1
	if [[ -n $PUBKEY ]]; then
		asset SHA256SUMS.sig || die "В релизе нет подписи SHA256SUMS.sig"
		{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; echo "$PUBKEY" | base64 -d; } > "$tmp/pub.der"
		base64 -d "$tmp/SHA256SUMS.sig" > "$tmp/sig.bin"
		openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/pub.der" -rawin -in "$tmp/SHA256SUMS" -sigfile "$tmp/sig.bin" >/dev/null \
			|| die "Подпись SHA256SUMS не прошла проверку"
		info "Подпись релиза верна"
	fi
	(cd "$tmp" && grep " vpnstack-linux-$ARCH\$" SHA256SUMS | sha256sum -c --quiet -) || die "Контрольная сумма не совпала"
	install -m 0755 "$tmp/vpnstack-linux-$ARCH" "$BIN"
}

from_source() {
	info "Сборка из исходников"
	local gover gofile gosum
	gh -o "$tmp/go.json" "https://go.dev/dl/?mode=json"
	gover=$(jq -r '[.[] | select(.stable)][0].version' "$tmp/go.json")
	gofile=$(jq -r --arg a "$ARCH" '[.[] | select(.stable)][0].files[] | select(.os=="linux" and .arch==$a and .kind=="archive") | .filename' "$tmp/go.json")
	gosum=$(jq -r --arg a "$ARCH" '[.[] | select(.stable)][0].files[] | select(.os=="linux" and .arch==$a and .kind=="archive") | .sha256' "$tmp/go.json")
	if [[ ! -x /opt/vpnstack/go/bin/go ]]; then
		info "Go $gover"
		curl -fsSL -o "$tmp/$gofile" "https://go.dev/dl/$gofile"
		echo "$gosum  $tmp/$gofile" | sha256sum -c --quiet - || die "Сумма Go не совпала"
		mkdir -p /opt/vpnstack && rm -rf /opt/vpnstack/go && tar -C /opt/vpnstack -xzf "$tmp/$gofile"
	fi
	local url="https://github.com/$REPO"
	[[ -n $TOKEN ]] && url="https://x-access-token:$TOKEN@github.com/$REPO"
	git clone -q --depth 1 ${VPNSTACK_REF:+--branch "$VPNSTACK_REF"} "$url" "$tmp/src"
	local commit; commit=$(git -C "$tmp/src" rev-parse --short HEAD)
	(cd "$tmp/src" && CGO_ENABLED=0 /opt/vpnstack/go/bin/go build -trimpath \
		-ldflags "-s -w -X github.com/lineSence/vpnstack/internal/version.Version=v0.0.0-src.$commit -X github.com/lineSence/vpnstack/internal/version.Commit=$commit" \
		-o "$tmp/vpnstack" ./cmd/vpnstack)
	install -m 0755 "$tmp/vpnstack" "$BIN"
}

if [[ ${VPNSTACK_FROM_SOURCE:-0} == 1 ]] || ! from_release; then
	[[ ${VPNSTACK_FROM_SOURCE:-0} == 1 ]] || warn "Готового релиза нет — собираю из исходников"
	from_source
fi
info "Установлен $($BIN version)"

install -d -m 0755 /etc/vpnstack
if [[ -n $TOKEN ]]; then
	printf 'VPNSTACK_GITHUB_TOKEN=%s\n' "$TOKEN" > /etc/vpnstack/env
	chmod 0600 /etc/vpnstack/env
	info "Токен сохранён в /etc/vpnstack/env (нужен для OTA из приватного репозитория)"
fi

"$BIN" setup

if [[ ${VPNSTACK_NO_MENU:-0} != 1 ]] && [[ -e /dev/tty ]]; then
	exec "$BIN" </dev/tty
fi
info "Готово. Запустите: sudo vpnstack"
