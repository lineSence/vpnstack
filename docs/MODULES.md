# Внешние модули

Сервис можно добавить без пересборки vpnstack: положите каталог в `/etc/vpnstack/modules.d/<id>/`.
Модуль появится в `vpnstack modules`, меню и панели и получит те же возможности, что встроенные:
проверку портов, маршрут на общем входе 443, сайт и сертификат в Caddy, slice для учёта CPU/RAM,
пользователей и ссылки.

## module.json

```json
{
  "id": "naive",
  "title": "NaiveProxy",
  "description": "HTTPS-прокси на базе Caddy forwardproxy",
  "order": 80,
  "params": [
    {"key": "domain", "label": "Домен", "type": "domain", "required": true},
    {"key": "port", "label": "Внутренний порт", "type": "port", "advanced": true}
  ],
  "defaults": {"port": "$random_port", "secret": "$hex16"},
  "needs": [
    {"proto": "tcp", "port_param": "port", "purpose": "naive за общим входом",
     "edge_only": true, "edge": {"sni_params": ["domain"], "proxy_protocol": false, "priority": 40}}
  ],
  "units": ["naive.service"],
  "users": true,
  "hooks": {
    "install": "install.sh",
    "apply": "install.sh",
    "remove": "remove.sh",
    "latest": "latest.sh",
    "add_user": "user.sh",
    "del_user": "user.sh",
    "artifacts": "user.sh",
    "traffic": "traffic.sh"
  },
  "timeout": 1800
}
```

Поля:

* `params` — как у встроенных модулей: `type` = `string|int|bool|select|domain|port|list|secret`,
  `required`, `advanced` (показывать только в ручном режиме), `restart`, `options`, `help`.
* `defaults` — значения по умолчанию; специальные: `$random_port`, `$hex16`, `$password`.
* `needs` — порты: `port` или `port_param`, `public`, `edge` (маршрут TCP 443 по SNI из параметров `sni_params`,
  backend — `127.0.0.1:<port>`), `edge_only` / `ports_only` — только для одного режима входа.
* `caddy_site` — `{"host_param": "domain", "block": "reverse_proxy 127.0.0.1:{param:port}"}`: Caddy выпустит
  сертификат и обслужит сайт; пустой `block` — сайт-прикрытие.
* `units` — systemd-юниты (после установки к ним добавляется `Slice=vpnstack-<id>.slice`).
* `hooks` — исполняемые файлы (путь относительно каталога модуля). Обязателен только `install`.

## Протокол хуков

Хук получает на stdin JSON:

```json
{
  "hook": "add_user",
  "service": {"enabled": true, "installed": true, "version": "…", "params": {…}, "secrets": {…}, "users": [ … ]},
  "stack": {"public_ip": "203.0.113.1", "email": "…", "edge_enabled": true, "edge_port": 443, "site_dir": "/var/lib/vpnstack/site"},
  "user": {"name": "alice", "data": {}},
  "name": "alice",
  "opts": {}
}
```

Переменные окружения: `VPNSTACK_HOOK`, `VPNSTACK_SERVICE`. stderr попадает в журнал задачи, stdout — необязательный JSON:

```json
{
  "params":   {"key": "value"},
  "secrets":  {"key": "value"},
  "version":  "1.2.3",
  "state":    "running",
  "detail":   "текст для панели",
  "user":     {"password": "…"},
  "artifacts":[{"kind": "uri", "title": "Ссылка", "value": "naive+https://…", "qr": true}],
  "traffic":  {"alice": {"rx": 123, "tx": 456}}
}
```

* `install` / `apply` / `update` — поставить/применить конфигурацию; можно вернуть `params`, `secrets`, `version`.
* `remove` — `opts.purge` = `"true"`, если удалить данные.
* `status` — `state` (`running|stopped|failed|partial`) и `detail`; без хука статус берётся по `units`.
* `latest` — `version` (последняя доступная).
* `add_user` — вернуть данные пользователя в `user`; `del_user` — удалить (пользователь уже убран из `service.users`).
* `artifacts` — ссылки/файлы для пользователя `name` (`kind`: `uri|file|token|text`, для `file` — `name`).
* `traffic` — накопительные счётчики байт по пользователям.

Ненулевой код возврата — ошибка операции.

## Необязательные интерфейсы встроенных модулей

Встроенный модуль (`internal/modules/*.go`) может дополнительно реализовать:

* `module.Fetcher` — `Prefetch(env, s)`: заранее скачать программы/образы, не трогая работающие сервисы.
  Используется при переносе (`vpnstack adopt migrate`), чтобы простой длился секунды.
* `module.Rollbacker` — `Rollback(env, s, prevVersion)`: вернуть предыдущую версию. `vpnstack update` после
  обновления ждёт, пока сервис заработает и откроет порты, и при неудаче вызывает `Rollback`
  (бинарники хранят предыдущую копию `*.prev`, Docker — прежний тег образа).
