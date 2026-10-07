# Архитектура vpnstack

## Компоненты

| Пакет | Назначение |
|---|---|
| `cmd/vpnstack` | CLI, меню, `serve` (панель + статистика + обслуживание), `edge` (общий вход 443), `setup`, `ota-guard` |
| `cmd/vpnstack-sign` | ключи ed25519 и подпись `SHA256SUMS` релиза |
| `internal/core` | движок: установка/настройка/удаление, служебная инфраструктура, пользователи |
| `internal/plan` | проверка совместимости: дубли портов, занятость посторонними, пересечение SNI, DNS |
| `internal/module` | контракт модуля, реестр, внешние модули по манифесту |
| `internal/modules` | встроенные модули: caddy, edge (служебные), fptn, tgwp, telemt, xray, awg, hysteria |
| `internal/edge` | маршрутизатор TCP по SNI из ClientHello, PROXY v2, счётчики, перечитывание по SIGHUP |
| `internal/netfilter` | таблица nftables `inet vpnstack`, sysctl |
| `internal/stats` | сбор CPU/RAM (cgroup v2), трафика (edge, nft, API сервисов), кольцевые буферы |
| `internal/panel` | HTTP API + встроенный интерфейс (vanilla JS), авторизация |
| `internal/ota` | самообновление с проверкой подписи и откатом |
| `internal/tui` | интерактивное меню и мастер установки |
| `internal/sys` | exec, systemd, загрузка релизов GitHub с проверкой сумм, сеть, cgroup |

## Файлы на сервере

```
/usr/local/bin/vpnstack(.prev)        бинарник (+ предыдущий для отката)
/etc/vpnstack/stack.json              состояние: параметры, секреты, пользователи (0600)
/etc/vpnstack/edge.json               маршруты общего входа
/etc/vpnstack/nft.conf                правила nftables (vpnstack-nft.service)
/etc/vpnstack/<svc>/                  конфигурации сервисов (caddy, xray, hysteria, telemt)
/etc/vpnstack/modules.d/<id>/         внешние модули
/etc/vpnstack/env                     токен GitHub (если репозиторий приватный)
/opt/vpnstack/bin/                    caddy, hysteria, telemt;  /opt/vpnstack/xray/ — xray + geo-файлы
/opt/vpnstack/fptn/                   docker-compose.yml, fptn.env, данные FPTN
/var/lib/vpnstack/caddy/              сертификаты Caddy
/var/lib/vpnstack/site/               сайт-прикрытие (можно заменить своим)
/var/lib/vpnstack/stats.json          статистика
/var/backups/vpnstack/                резервные копии перезаписываемых файлов
/etc/sysctl.d/90-vpnstack.conf        BBR, буферы UDP 16 МБ, ip_forward
```

## Юниты

`vpnstack.service` (serve), `vpnstack-edge.service`, `vpnstack-caddy.service`, `vpnstack-xray.service`,
`vpnstack-hysteria.service`, `vpnstack-telemt.service`, `vpnstack-fptn.service` (docker compose),
`awg-quick@awgvs0.service`, `tproxy-server.service` + `mtproxy.service`, `vpnstack-nft.service`.
Все — в `vpnstack-<id>.slice` внутри `vpnstack.slice`.

## Жизненный цикл установки

1. Параметры → `AutoDefaults` (порты, ключи X25519, секреты, подсети) → проверка обязательных.
2. `plan.Build`: маршруты 443, сайты Caddy, потребность в Caddy/edge, конфликты (с PID и юнитом-владельцем).
3. Служебные компоненты: Caddy (сайты всех сервисов) и edge ставятся/обновляются/убираются по необходимости.
4. nftables + sysctl.
5. `Module.Install` → первый пользователь `user1` → ссылки/QR.

Удаление сервиса пересчитывает план: ненужные Caddy/edge снимаются, маршруты и сайты убираются.

## Общий вход (edge)

Читает ClientHello (до 64 КБ, в том числе разбитый на несколько TLS-записей — актуально для постквантовых ClientHello; таймаут 10 с), извлекает SNI, выбирает маршрут по приоритету
(поддомены совпадают, как в FPTN `ALLOWED_SNI_LIST`), при необходимости отправляет PROXY v2 и проксирует байты
без расшифровки. Неизвестный SNI → маршрут по умолчанию (Caddy, без него — REALITY, который пересылает
такие соединения на настоящий сайт-цель). Счётчики rx/tx/соединений по маршрутам — `127.0.0.1:8898/stats`.

Caddy принимает PROXY v2 только от 127.0.0.1 (`proxy_protocol { allow 127.0.0.1/32 }`); соединения без заголовка
с loopback тоже принимаются — так telemt отдаёт сканеры своему домену в Caddy (`mask_host = 127.0.0.1:7443`).

## Сертификаты

Caddy — единственный ACME-клиент (HTTP-01 на 80 и TLS-ALPN через edge). Для Hysteria vpnstack копирует
сертификат домена из хранилища Caddy в `/etc/vpnstack/hysteria/` и проверяет обновление каждые 10 минут;
Hysteria перечитывает файлы сертификата сама, без перезапуска.

## Статистика

Раз в минуту: CPU хоста (/proc/stat), память, интерфейс по умолчанию; CPU/память каждого slice (cgroup v2);
трафик маршрутов edge и UDP-счётчики nftables; трафик пользователей из API сервисов. Счётчики накопительные —
хранятся приращения (сброс счётчика при перезапуске сервиса учитывается). Поминутно — 24 часа, почасово — 30 дней,
итоги за всё время; файл `/var/lib/vpnstack/stats.json` сохраняется каждые 5 минут.

## OTA

`SHA256SUMS` релиза подписан ed25519 (секрет CI), открытый ключ встраивается в бинарник при сборке.
Новая версия проверяется (`vpnstack version`), ставится атомарно, старая остаётся `vpnstack.prev`;
`systemd-run --on-active=180` запускает `vpnstack.prev ota-guard`: если новая версия за это время не
подтвердила работу (минута стабильной работы `serve`), бинарник откатывается и службы перезапускаются.
