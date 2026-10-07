package modules

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHysteriaTLSPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			for _, path := range []string{cert, key} {
				if err := os.WriteFile(path, []byte("unchanged certificate/key"), mode); err != nil {
					t.Fatal(err)
				}
			}
			source := filepath.Join(dir, "source.crt")
			if err := os.WriteFile(source, []byte("unchanged certificate/key"), 0o644); err != nil {
				t.Fatal(err)
			}
			changed, err := copyIfChanged(source, cert, 0o644)
			if err != nil || changed {
				t.Fatalf("copy should be unchanged: %v %v", changed, err)
			}
			if err := hysteriaTLSPermissions(cert, key, os.Getgid()); err != nil {
				t.Fatal(err)
			}
			for path, want := range map[string]os.FileMode{cert: 0o644, key: 0o640} {
				st, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if st.Mode().Perm() != want {
					t.Errorf("%s mode %o want %o", path, st.Mode().Perm(), want)
				}
				if st.Sys().(*syscall.Stat_t).Gid != uint32(os.Getgid()) {
					t.Errorf("wrong group: %s", path)
				}
				b, err := os.ReadFile(path)
				if err != nil || string(b) != "unchanged certificate/key" {
					t.Fatal("TLS data changed")
				}
			}
		})
	}
}

func TestHysteriaTLSPermissionsMissingKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("cert"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := hysteriaTLSPermissions(cert, filepath.Join(dir, "missing.key"), os.Getgid()); err == nil {
		t.Fatal("permission errors must propagate")
	}
}
