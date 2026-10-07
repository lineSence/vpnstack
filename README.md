# vpnstack

Оркестратор VPN/прокси-сервисов на одном сервере Ubuntu: ставит, настраивает, связывает между собой и обновляет
**FPTN, TG WEB proxy, MTProto (telemt), VLESS + REALITY (Xray), AmneziaWG и Hysteria 2**, следит за конфликтами портов и SNI,
считает CPU/RAM/трафик по каждому сервису и пользователю и даёт веб-панель (только через SSH-туннель).

Один статический бинарник на Go без внешних зависимостей. Сервисы ставятся из **официальных релизов с проверкой
контрольных сумм** (FPTN — официальный Docker-образ, TG WEB proxy — официальный `tproxy-server` закреплённой ревизии).

> Статус: ранняя версия (v0.1). Конфигурации проверены настоящими бинарниками последних версий
> (Caddy 2.11.7, Xray 26.3.27, Hysteria 2.13.0, telemt 3.5.14), но полный прогон на чистом сервере ещё предстоит.

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/lineSence/vpnstack/main/install.sh | sudo bash
```

Пока репозиторий приватный, нужен токен GitHub с доступом на чтение (fine-grained, *Contents: Read*):

```bash
curl -fsSL -H "Authorization: Bearer github_pat_…" \
  https://raw.githubusercontent.com/lineSence/vpnstack/main/install.sh | sudo VPNSTACK_GITHUB_TOKEN=github_pat_… bash
```

Если релизов ещё нет, установщик сам соберёт vpnstack из исходников (скачает Go с go.dev с проверкой SHA-256).
После установки запускается интерактивное меню: выбираете сервисы, режим **автоматически** (спросит только домены)
или **вручную** (все параметры), vpnstack проверяет конфликты и ставит всё по очереди. Повторный вход — `sudo vpnstack`.

Неинтерактивно:

```bash
sudo vpnstack install xray hysteria awg \
  --set hysteria.domain=hy.example.com
sudo vpnstack install tgwp telemt --set tgwp.domain=tg.example.com --set telemt.tls_domain=mt.example.com
```

## Как устроено

```
TCP 80   → Caddy (ACME HTTP-01, редирект)
TCP 443  → vpnstack edge — маршрутизация по SNI (без расшифровки TLS):
             tg.example.com / прочие свои домены → Caddy 127.0.0.1:7443 (PROXY v2) → TG WEB proxy, сайты-прикрытия
             SNI REALITY (www.microsoft.com)    → Xray 127.0.0.1:10443 (PROXY v2)
             домен fake-TLS telemt              → telemt 127.0.0.1:10444 (PROXY v2)
             домены-приманки FPTN (sber.ru, …)  → FPTN 127.0.0.1:10445
             всё остальное                       → Caddy (или REALITY, если доменов нет)
UDP 443  → Hysteria 2 (сертификат выпускает Caddy, vpnstack копирует его)
UDP x    → AmneziaWG (случайный порт 30000–60000)
127.0.0.1:8899 → панель vpnstack (через ssh -L)
```

* Caddy — единственный ACME-клиент; конфликты «Caddy против Hysteria за 443» исключены.
* Каждый сервис живёт в своём systemd slice `vpnstack-<id>.slice` (Docker FPTN — через `cgroup_parent`), отсюда CPU/RAM.
* Трафик: счётчики общего входа (TCP 443), nftables (UDP-порты), API сервисов по пользователям
  (Xray StatsService, Hysteria `/traffic`, telemt `/v1/users`, `awg show dump`).
* Внутренние порты закрыты снаружи таблицей nftables `inet vpnstack`; NAT для AmneziaWG — там же.

Подробно: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), сведения о версиях и форматах: [docs/SERVICES.md](docs/SERVICES.md).

## Сервисы

| id | Сервис | Порт | Пользователи | Ссылки/конфиги | Трафик по пользователям |
|---|---|---|---|---|---|
| `fptn` | FPTN (Docker) | TCP 443 по SNI | да (`fptn-passwd`) | токен FPTN | нет (см. ограничения) |
| `tgwp` | TG WEB proxy (tproxy-server + MTProxy) | TCP 443 через Caddy | одна ссылка | `t.me/webproxy?...` | — |
| `telemt` | MTProto-прокси telemt | TCP 443 по SNI | да | `tg://proxy?...` (ee-секрет) | сумма rx+tx |
| `xray` | VLESS + REALITY + Vision | TCP 443 по SNI | да | `vless://...` | да |
| `awg` | AmneziaWG 3.1 (3.0 / 2.0 / 1.5) | UDP случайный | да | `.conf` + QR | да |
| `hysteria` | Hysteria 2 | UDP 443 | да | `hysteria2://...` | да |

Для доменов нужны A-записи на сервер (поддомены: `tg.`, `hy.`, `mt.` и т. п.). Без домена Hysteria работает
с самоподписанным сертификатом и `pinSHA256`, telemt — с чужим доменом fake-TLS.

## Панель

Слушает только `127.0.0.1:8899`. С вашего компьютера:

```bash
ssh -N -L 8899:127.0.0.1:8899 root@SERVER
# http://127.0.0.1:8899
```

Обзор (CPU/RAM/трафик хоста и сервисов, графики за 24 ч / 7 / 30 дней), установка/настройка/удаление сервисов,
проверка конфликтов с кнопкой «остановить мешающий юнит», пользователи со ссылками и QR, журналы, OTA.
Пароль — PBKDF2-SHA256, сессии HttpOnly + SameSite=Strict + CSRF, ограничение попыток, опционально TOTP
(`sudo vpnstack panel totp`). Сменить пароль: `sudo vpnstack panel passwd`.

## Обновления

* Сервисы: `sudo vpnstack update [svc|all]` или кнопка в панели — ставится последний релиз канала `stable`
  (или `prerelease`: `vpnstack set channel=prerelease`), пользователи и настройки сохраняются.
* Сам vpnstack (OTA): `sudo vpnstack self-update`, кнопка в панели или автообновление (`vpnstack set ota_auto=true`).
  Релиз подписан ed25519; новая версия должна подтвердить работу за 3 минуты, иначе таймер вернёт предыдущую.

### Подпись релизов (один раз)

```bash
go run ./cmd/vpnstack-sign keygen
# VPNSTACK_SIGNING_KEY → Settings → Secrets → Actions
# VPNSTACK_PUBLIC_KEY  → Settings → Variables → Actions
git tag v0.1.0 && git push --tags     # GitHub Actions соберёт amd64/arm64, подпишет и опубликует релиз
```

Сборка без открытого ключа OTA не выполняет (кроме `VPNSTACK_OTA_ALLOW_UNSIGNED=1`).
Для приватного репозитория OTA использует токен из `/etc/vpnstack/env`.

## Свои сервисы

Новые сервисы добавляются без пересборки: каталог `/etc/vpnstack/modules.d/<id>/` с `module.json` и скриптами-хуками
(JSON на stdin/stdout). Такой модуль получает порты, маршрут на общем входе, сайт в Caddy, slice для статистики,
пользователей и место в панели. См. [docs/MODULES.md](docs/MODULES.md). Встроенные модули — `internal/modules/*.go`.

## Команды

```
vpnstack                       меню
vpnstack install [svc...] [--set svc.key=value]
vpnstack set <svc> key=value   изменить параметры (перегенерация конфигурации)
vpnstack set email=… edge_mode=sni|ports channel=stable|prerelease ota_auto=true
vpnstack users <svc> [list|add NAME|del NAME|show NAME]
vpnstack links tgwp
vpnstack status | plan | doctor | modules
vpnstack update [svc|all] | self-update [--check]
vpnstack remove <svc> [--purge]
```

## Ограничения и заметки

* **FPTN**: учёт трафика по пользователям не реализован — метрики FPTN доступны только клиенту протокола FPTN;
  есть суммарный трафик сервиса (общий вход) и CPU/RAM контейнера. PROXY protocol FPTN не поддерживает,
  поэтому за общим входом он видит адрес 127.0.0.1 (фильтры и лимиты по пользователю работают).
* **TG WEB proxy** требует x86_64 (официальная сборка MTProxy). Установщик `tproxy-server` используется штатный,
  из него вырезается только установка собственного Caddy (проверено на ревизии `c8adb8b`; на другой ревизии
  установка остановится с понятной ошибкой).
* **AmneziaWG**: модуль ядра из PPA `amnezia/ppa`; если не собрался — userspace `amneziawg-go` из исходников.
  По умолчанию AWG 3.1 (HeaderProtectionKey, ContentPaddingAddition, RandomTrailers) — нужны клиенты с поддержкой AWG 3 (AmneziaVPN 5.0+). Для старых клиентов — `awg_version=2.0` или `1.5`.
* SNI разных сервисов на общем входе не должны пересекаться (с учётом поддоменов) — `vpnstack plan` это проверяет.
* Перезапуск Xray/Hysteria/telemt при изменении пользователей кратко рвёт текущие соединения этого сервиса.
