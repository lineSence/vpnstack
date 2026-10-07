package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/lineSence/vpnstack/internal/sys"
)

// Версия установленного файла хранится рядом: <bin>.tag (и <bin>.prev.tag для отката).
// Это позволяет скачать программу заранее (Prefetch), а при установке не качать повторно.

func binTag(bin string) string {
	b, err := os.ReadFile(bin + ".tag")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// haveBin — нужная версия уже лежит на месте.
func haveBin(bin, tag string) bool {
	return tag != "" && sys.Exists(bin) && binTag(bin) == tag
}

// installBin ставит новый файл, сохраняя прежний как .prev вместе с его версией.
func installBin(src, bin, tag string) error {
	if t := binTag(bin); t != "" && sys.Exists(bin) {
		_ = os.WriteFile(bin+".prev.tag", []byte(t+"\n"), 0o644)
	}
	if err := sys.InstallBinary(src, bin); err != nil {
		return err
	}
	return os.WriteFile(bin+".tag", []byte(tag+"\n"), 0o644)
}

// restoreBin возвращает предыдущую версию файла (после неудачного обновления).
func restoreBin(bin string) (string, error) {
	prev := bin + ".prev"
	if !sys.Exists(prev) {
		return "", fmt.Errorf("нет предыдущей версии %s", bin)
	}
	tag := binTag(prev)
	if err := os.Rename(bin, bin+".bad"); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(prev, bin); err != nil {
		_ = os.Rename(bin+".bad", bin)
		return "", err
	}
	if tag != "" {
		_ = os.WriteFile(bin+".tag", []byte(tag+"\n"), 0o644)
		_ = os.Remove(prev + ".tag")
	}
	return tag, nil
}
