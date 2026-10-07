# Сервисы: версии, источники, форматы

Сведения проверены по исходникам и релизам **на 7 октября 2026**. vpnstack всегда берёт последний релиз
выбранного канала, поэтому версии ниже — ориентир, а не закрепление (кроме tproxy-server).

| Сервис | Репозиторий | Проверенная версия | Что ставится | Проверка целостности |
|---|---|---|---|---|
| Caddy | caddyserver/caddy | v2.11.7 | `caddy_<v>_linux_<arch>.tar.gz` | SHA-512 из `caddy_<v>_checksums.txt` |
| Xray-core | XTLS/Xray-core | v26.3.27 (stable; есть пре-релизы v26.9.x) | `Xray-linux-64.zip` / `Xray-linux-arm64-v8a.zip` | SHA2-256 из `.dgst` |
| Hysteria | apernet/hysteria | app/v2.13.0 | `hysteria-linux-amd64[-avx]` / `-arm64` | SHA-256 из `hashes.txt` |
| telemt | telemt/telemt | 3.5.14 (2026-10-05) | `telemt-<arch>-linux-gnu.tar.gz` | SHA-256 из `.sha256` |
| AmneziaWG | amnezia-vpn/* | актуальная в PPA (jammy, noble, resolute) | `ppa:amnezia/ppa` → `amneziawg` (DKMS) | подпись apt |
| FPTN | batchar2/fptn | 0.4.6 (2026-10-03) | Docker `fptnvpn/fptn-vpn-server:<v>` | реестр Docker |
| tproxy-server | telegramdesktop/tproxy-server | `c8adb8b` (2026-09-29) | git + штатный `deploy/install.sh` | закреплённый коммит; MTProxy и Go — суммы в установщике |
| Go (для сборки) | go.dev | последний stable (1.27.x) | архив с go.dev | SHA-256 из `go.dev/dl/?mode=json` |

## Caddy

* Глобально: `admin 127.0.0.1:2029`, `http_port 80`, `https_port 7443` (за edge) или 443 (режим портов),
  для сервера `:7443` — `listener_wrappers { proxy_protocol { allow 127.0.0.1/32 } tls }`, `protocols h1 h2`
  (HTTP/3 выключен — UDP 443 у Hysteria), таймауты `read_header 10s`, `read_body 60s` (как в tproxy-server).
* Блок сайта TG WEB proxy — копия штатного `deploy/Caddyfile` tproxy-server (encode, HSTS, `reverse_proxy 127.0.0.1:8080`
  с `response_header_timeout 40s`, единый `handle_errors`).
* Сертификаты: `$XDG_DATA_HOME/caddy/certificates/<issuer>/<domain>/<domain>.crt|key`, где `XDG_DATA_HOME=/var/lib/vpnstack/caddy`.

## Xray (VLESS + REALITY)

* Inbound `vless`, `decryption: none`, клиенты `{id, flow: xtls-rprx-vision, email}`.
* `streamSettings`: `network: raw`, `security: reality`, `realitySettings {target, serverNames, privateKey, shortIds}`,
  за edge — `sockopt.acceptProxyProtocol: true` и `listen 127.0.0.1:10443`.
* Ключи X25519 генерирует vpnstack (как `xray x25519`: закрытый и открытый ключ — base64url без `=`).
* Статистика: `api {listen 127.0.0.1:10085, services [HandlerService, StatsService]}`, `policy.levels.0.statsUserUplink/Downlink`;
  чтение — `xray api statsquery --server=127.0.0.1:10085` (имена `user>>>NAME>>>traffic>>>uplink|downlink`).
* Ссылка: `vless://UUID@IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=…&fp=chrome&pbk=…&sid=…&type=tcp#NAME`.
* SNI по умолчанию `www.microsoft.com` — меняйте на сайт с TLS 1.3 + HTTP/2, близкий к серверу; он не должен
  пересекаться с доменами FPTN и telemt.

## Hysteria 2

* `listen :443`, `tls {cert, key}` (файлы перечитываются на лету), `auth {type: userpass, userpass: {name: pass}}`,
  `trafficStats {listen 127.0.0.1:9998, secret}`, `masquerade {type: file, file.dir: /var/lib/vpnstack/site}`,
  опционально `obfs.salamander` и `bandwidth`.
* API статистики: `GET /traffic` → `{"user": {"tx": N, "rx": N}}`, `GET /online`, `POST /kick`; заголовок `Authorization: <secret>`.
* Ссылка: `hysteria2://USER:PASS@HOST:443/?sni=HOST[&obfs=salamander&obfs-password=…][&insecure=1&pinSHA256=…]#NAME`
  (при `auth.type=userpass` строка авторизации — `user:pass`).
* Запуск: `hysteria server --config … --disable-update-check`.

## telemt (MTProto)

* TOML: `[general] use_middle_proxy`, `[general.modes] tls = true` (classic/secure выключены),
  `[general.links] public_host/public_port`, `[server] port`, `proxy_protocol = true`,
  `proxy_protocol_trusted_cidrs = ["127.0.0.1/32"]`, `[[server.listeners]] ip = "127.0.0.1"`,
  `[server.api] listen = "127.0.0.1:9091"`, `whitelist`, `auth_header`,
  `[censorship] tls_domain`, `mask = true`, `tls_emulation = true`, `tls_front_dir`, `mask_host/mask_port`,
  `[access.users] name = "32 hex"`.
* Если домен fake-TLS указывает на сервер — `mask_host = 127.0.0.1`, `mask_port = 7443`: сканеры получают настоящий
  сайт Caddy с валидным сертификатом этого домена. Иначе маскировка идёт на сам `tls_domain:443`.
* Ссылка: `tg://proxy?server=HOST&port=443&secret=ee<32 hex><hex(tls_domain)>`.
* API: `GET /v1/users` → `{ok, data: [{username, total_octets, current_connections, links…}]}` (только сумма трафика).
* В telemt появился собственный транспорт `transport = "web"` (MTProxy WEB за внешним TLS-терминатором) — кандидат
  на будущую замену tproxy-server.

## AmneziaWG

* Установка: `add-apt-repository ppa:amnezia/ppa`, `linux-headers-$(uname -r)`, `apt install amneziawg`;
  интерфейс `awgvs0`, конфиг `/etc/amnezia/amneziawg/awgvs0.conf`, юнит `awg-quick@awgvs0`.
* Параметры: `Jc` 4–12, `Jmin 8`, `Jmax 80`, `S1`/`S2` 15–150 с `S1 + 56 ≠ S2`, `S3`/`S4` (2.0),
  `H1–H4` — непересекающиеся диапазоны в 5…2147483647 (2.0) или одиночные значения (1.5), `I1` — необязательная сигнатура.
* Пиры добавляются без разрыва: `awg syncconf awgvs0 <(awg-quick strip awgvs0)`; трафик — `awg show awgvs0 dump`.
* NAT — `masquerade` в таблице `inet vpnstack`, `net.ipv4.ip_forward = 1`.
* AWG 3 (Header Protection) пока не включается: требует S1–S4 ≥ 12 и поддержки клиентами.

## FPTN

* Официальный `docker-compose.yml` (privileged, NET_ADMIN…, `/dev/net/tun`, sysctl BBR, сеть IPv4+IPv6),
  дополнительно `cgroup_parent: vpnstack-fptn.slice`; публикация `127.0.0.1:10445:443` за edge.
* Переменные — как в официальном `.env`: `SERVER_EXTERNAL_IPS` (обязательно), `ENABLE_DETECT_PROBING`,
  `ALLOWED_SNI_LIST` (поддомены совпадают; неизвестный SNI → первый доступный домен-приманка),
  фильтры рекламы/торрентов/спама/чёрного списка, `MAX_ACTIVE_SESSIONS_PER_USER`, `MTU_SIZE`, DNS unbound.
* Пользователи: `fptn-passwd --add-user NAME --bandwidth MBPS` (пароль дважды в stdin), `--del-user`;
  токен: `token-generator --user --password --server-ip --port`.
* Сертификат сервера: `openssl genrsa` + самоподписанный, как в README FPTN.
* Метрики Prometheus FPTN (`/api/v1/metrics/<key>`) отдаются только клиенту протокола FPTN — по пользователям
  трафик пока не считается.

## TG WEB proxy (tproxy-server)

* Штатный `deploy/install.sh` закреплённой ревизии с вырезанными фрагментами установки Caddy (скачивание бинарника,
  Caddyfile, caddy.service, `caddy validate`, запуск). Остальное — без изменений: сборка MTProxy (`f36d8af`, SHA-256),
  Go (если нет ≥ 1.20), тесты и сборка `tproxy-server`, `config.json`, `profiles.json`, nftables-таблица
  `tproxy_backend`, таймер обновления конфигурации MTProxy, автоопределение NAT.
* Внутренние порты: 8080 (relay), 8081 (admin, `/readyz`), 2398 и 8888 (MTProxy).
* Ссылка: `https://t.me/webproxy?server=HOST%2FBASE&secret=…`; при базовом пути секрет — base64url(`0x70` + байты секрета).
