package sys

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"time"
)

// WriteFileAtomic пишет файл через временный файл и rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// BackupDir — каталог резервных копий.
const BackupDir = "/var/backups/vpnstack"

// Backup копирует файл в каталог резервных копий с меткой времени.
// Отсутствующий файл не считается ошибкой.
func Backup(path string) error {
	src, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer src.Close()
	dst := filepath.Join(BackupDir, time.Now().Format("20060102-150405"), filepath.Base(path))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return err
}

// RandHex возвращает n случайных байт в hex.
func RandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Exists сообщает, существует ли путь.
func Exists(path string) bool { _, err := os.Stat(path); return err == nil }

// RandUint — криптослучайное число в [0, n).
func RandUint(n uint64) uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:]) % n
}
