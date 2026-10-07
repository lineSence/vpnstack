// Package version содержит сведения о сборке. Значения задаются через -ldflags.
package version

var (
	// Version — версия оркестратора (тег релиза), например v0.1.0.
	Version = "dev"
	// Commit — короткий хеш коммита.
	Commit = "none"
	// Repo — репозиторий GitHub, из которого берутся OTA-обновления.
	Repo = "lineSence/vpnstack"
	// SigningKey — публичный ключ ed25519 (base64) для проверки подписи релизов.
	// Пустой ключ отключает OTA (обновление без проверки подписи не выполняется).
	SigningKey = ""
)
