package panel

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lineSence/vpnstack/internal/core"
	"github.com/lineSence/vpnstack/internal/state"
)

// Пароль, сменённый из CLI (другой процесс), действует в работающей панели сразу,
// а фоновое сохранение панели его не затирает.
func TestPasswdFromCLI(t *testing.T) {
	state.Path = filepath.Join(t.TempDir(), "stack.json")
	old, _ := HashPassword("old-password")
	srv, _ := core.Open() // «панель»
	if err := srv.Mutate(func(st *state.Stack) error { st.Panel.PassHash = old; return nil }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // разные mtime
	cli, _ := core.Open()             // «vpnstack panel passwd»
	nw, _ := HashPassword("new-password")
	if err := cli.Mutate(func(st *state.Stack) error { st.Panel.PassHash = nw; return nil }); err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(srv.PanelAuth().PassHash, "new-password") {
		t.Fatal("панель не видит новый пароль")
	}
	srv.TryRun(func() { _ = srv.St.Save() }) // фоновая задача панели
	again, _ := state.Load()
	if !CheckPassword(again.Panel.PassHash, "new-password") {
		t.Fatal("панель затёрла новый пароль старым")
	}
}
