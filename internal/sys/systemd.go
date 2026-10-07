package sys

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// UnitDir — каталог юнитов, которыми управляет vpnstack.
const UnitDir = "/etc/systemd/system"

// WriteUnit записывает юнит и перечитывает конфигурацию systemd.
func WriteUnit(name, content string) error {
	if err := WriteFileAtomic(filepath.Join(UnitDir, name), []byte(content), 0o644); err != nil {
		return err
	}
	_, err := Run("systemctl", "daemon-reload")
	return err
}

// WriteDropIn записывает drop-in файл для юнита (например, привязку к slice).
func WriteDropIn(unit, file, content string) error {
	dir := filepath.Join(UnitDir, unit+".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := WriteFileAtomic(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		return err
	}
	_, err := Run("systemctl", "daemon-reload")
	return err
}

// RemoveUnit останавливает, отключает и удаляет юнит вместе с drop-in.
func RemoveUnit(name string) {
	_, _ = Run("systemctl", "disable", "--now", name)
	_ = os.Remove(filepath.Join(UnitDir, name))
	_ = os.RemoveAll(filepath.Join(UnitDir, name+".d"))
	_, _ = Run("systemctl", "daemon-reload")
}

// Systemctl выполняет действие над юнитами.
func Systemctl(action string, units ...string) error {
	_, err := Run("systemctl", append([]string{action}, units...)...)
	return err
}

// Active сообщает, запущен ли юнит.
func Active(unit string) bool {
	out, _ := Output("systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

// UnitState возвращает active/inactive/failed/unknown.
func UnitState(unit string) string {
	out, _ := Output("systemctl", "is-active", unit)
	s := strings.TrimSpace(out)
	if s == "" {
		return "unknown"
	}
	return s
}

// SliceUnit — содержимое slice-юнита для сервиса vpnstack (учёт CPU/RAM/IO).
func SliceUnit(id, title string) string {
	return fmt.Sprintf(`[Unit]
Description=vpnstack: %s
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
TasksAccounting=yes
`, title)
}

// SliceName — имя slice для модуля. Все сервисы вложены в vpnstack.slice.
func SliceName(id string) string { return "vpnstack-" + id + ".slice" }

// EnsureSlice создаёт slice модуля.
func EnsureSlice(id, title string) error {
	if err := WriteFileAtomic(filepath.Join(UnitDir, "vpnstack.slice"), []byte(SliceUnit("", "весь стек")), 0o644); err != nil {
		return err
	}
	return WriteUnit(SliceName(id), SliceUnit(id, title))
}

// AttachToSlice привязывает существующий юнит к slice модуля через drop-in.
func AttachToSlice(unit, id string) error {
	return WriteDropIn(unit, "10-vpnstack-slice.conf", "[Service]\nSlice="+SliceName(id)+"\n")
}

// MainPID возвращает PID основного процесса юнита (0, если не запущен).
func MainPID(unit string) int {
	out, _ := Output("systemctl", "show", "-p", "MainPID", "--value", unit)
	pid, _ := strconv.Atoi(strings.TrimSpace(out))
	return pid
}
