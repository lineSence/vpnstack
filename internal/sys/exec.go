// Package sys — обёртки над системными вызовами: команды, systemd, загрузки, сеть, cgroup.
package sys

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Log — куда пишется вывод команд (журнал задачи). По умолчанию — stderr.
var Log io.Writer = os.Stderr

// Run выполняет команду, вывод дублируется в Log. Возвращает объединённый вывод.
func Run(name string, args ...string) (string, error) {
	return RunCtx(context.Background(), nil, name, args...)
}

// RunIn выполняет команду со stdin.
func RunIn(stdin string, name string, args ...string) (string, error) {
	return RunCtx(context.Background(), strings.NewReader(stdin), name, args...)
}

// RunCtx — общий вариант с контекстом и stdin.
func RunCtx(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	w := io.MultiWriter(&buf, Log)
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Stdin = stdin
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// Output выполняет команду без записи в журнал (для опросов статистики).
func Output(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	b, err := cmd.Output()
	return string(b), err
}

// Has сообщает, доступна ли команда в PATH.
func Has(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Logf пишет строку в журнал.
func Logf(format string, a ...any) { fmt.Fprintf(Log, format+"\n", a...) }
