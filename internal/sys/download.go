package sys

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HTTP — клиент с таймаутом. Редиректы (в т.ч. на переименованные репозитории GitHub)
// выполняются автоматически.
var HTTP = &http.Client{Timeout: 10 * time.Minute}

// GitHubToken — необязательный токен (нужен для приватных репозиториев и обхода лимита API).
var GitHubToken = os.Getenv("VPNSTACK_GITHUB_TOKEN")

// Release — релиз GitHub.
type Release struct {
	Tag        string  `json:"tag_name"`
	Prerelease bool    `json:"prerelease"`
	Published  string  `json:"published_at"`
	Assets     []Asset `json:"assets"`
}

// Asset — файл релиза.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	API  string `json:"url"`
}

// Find возвращает файл релиза по точному имени.
func (r *Release) Find(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

func ghGet(url string, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "vpnstack")
	if GitHubToken != "" && strings.Contains(url, "github.com") {
		req.Header.Set("Authorization", "Bearer "+GitHubToken)
	}
	resp, err := HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

// LatestRelease возвращает последний релиз. stable=true — только стабильные
// (endpoint /releases/latest), иначе — самый свежий, включая pre-release.
func LatestRelease(repo string, stable bool) (*Release, error) {
	if stable {
		resp, err := ghGet("https://api.github.com/repos/"+repo+"/releases/latest", "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var r Release
		return &r, json.NewDecoder(resp.Body).Decode(&r)
	}
	resp, err := ghGet("https://api.github.com/repos/"+repo+"/releases?per_page=10", "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rs []Release
	if err := json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, errors.New("в репозитории " + repo + " нет релизов")
	}
	return &rs[0], nil
}

// ReleaseByTag возвращает релиз по тегу.
func ReleaseByTag(repo, tag string) (*Release, error) {
	resp, err := ghGet("https://api.github.com/repos/"+repo+"/releases/tags/"+tag, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r Release
	return &r, json.NewDecoder(resp.Body).Decode(&r)
}

// Download скачивает URL в файл и возвращает SHA-256.
func Download(url, dst string) (string, error) {
	resp, err := ghGet(url, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	h5 := sha512.New()
	if _, err := io.Copy(io.MultiWriter(f, h, h5), resp.Body); err != nil {
		return "", err
	}
	lastSHA512 = hex.EncodeToString(h5.Sum(nil))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// lastSHA512 — SHA-512 последнего скачанного файла (Caddy публикует суммы SHA-512).
var lastSHA512 string

// FetchText скачивает небольшой текстовый файл (например, суммы).
func FetchText(url string) (string, error) {
	accept := ""
	if strings.Contains(url, "api.github.com/repos/") && strings.Contains(url, "/releases/assets/") {
		accept = "application/octet-stream"
	}
	resp, err := ghGet(url, accept)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), err
}

// ChecksumFor ищет SHA-256 для файла name в тексте вида "<hex>  [путь/]name"
// или в формате .dgst ("SHA2-256= <hex>" / "SHA256 (name) = <hex>").
func ChecksumFor(text, name string) string {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		f := strings.Fields(line)
		if len(f) == 2 && (len(f[0]) == 64 || len(f[0]) == 128) && (f[1] == name || strings.HasSuffix(f[1], "/"+name) || strings.TrimPrefix(f[1], "*") == name) {
			return strings.ToLower(f[0])
		}
		if len(f) == 1 && len(f[0]) == 64 && name == "" {
			return strings.ToLower(f[0])
		}
		up := strings.ToUpper(line)
		if strings.HasPrefix(up, "SHA2-256=") || strings.HasPrefix(up, "SHA256=") || (strings.HasPrefix(up, "SHA256 (") && strings.Contains(line, "=")) {
			v := strings.TrimSpace(line[strings.LastIndex(line, "=")+1:])
			if len(v) == 64 {
				return strings.ToLower(v)
			}
		}
	}
	return ""
}

// DownloadVerified скачивает файл и сверяет SHA-256 (или SHA-512 по длине суммы).
func DownloadVerified(url, dst, sum string) error {
	got, err := Download(url, dst)
	if err != nil {
		return err
	}
	if sum == "" {
		return fmt.Errorf("нет контрольной суммы для %s — установка без проверки запрещена", url)
	}
	if len(sum) == 128 {
		got = lastSHA512
	}
	if !strings.EqualFold(got, sum) {
		os.Remove(dst)
		return fmt.Errorf("контрольная сумма %s не совпала: %s != %s", filepath.Base(dst), got, sum)
	}
	return nil
}

// ExtractFile извлекает из zip или tar.gz один файл по имени (базовому) в dst.
func ExtractFile(archive, member, dst string, perm os.FileMode) error {
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.OpenReader(archive)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if filepath.Base(f.Name) == member && !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return err
				}
				defer rc.Close()
				return writeFrom(rc, dst, perm)
			}
		}
		return fmt.Errorf("%s не найден в %s", member, archive)
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) == member && h.Typeflag == tar.TypeReg {
			return writeFrom(tr, dst, perm)
		}
	}
	return fmt.Errorf("%s не найден в %s", member, archive)
}

func writeFrom(r io.Reader, dst string, perm os.FileMode) error {
	tmp := dst + ".new"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// InstallBinary атомарно ставит файл src в dst, сохраняя прежнюю версию как dst.prev.
func InstallBinary(src, dst string) error {
	if Exists(dst) {
		_ = os.Remove(dst + ".prev")
		if err := os.Link(dst, dst+".prev"); err != nil {
			_ = copyFile(dst, dst+".prev")
		}
	}
	if err := os.Chmod(src, 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if err := copyFile(src, dst+".new"); err != nil {
			return err
		}
		return os.Rename(dst+".new", dst)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeFrom(in, dst, 0o755)
}
