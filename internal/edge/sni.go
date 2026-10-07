// Package edge — общий вход на TCP 443: читает SNI из TLS ClientHello и, не
// расшифровывая трафик, передаёт соединение нужному сервису (Caddy, Xray Reality,
// telemt, FPTN). Реальный IP клиента передаётся по PROXY protocol v2.
package edge

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

var errNotTLS = errors.New("не TLS ClientHello")

// readClientHello читает из r первые TLS-записи, пока не соберёт ClientHello,
// и возвращает все прочитанные байты и SNI (пустой, если расширения нет).
func readClientHello(r io.Reader) ([]byte, string, error) {
	var raw, hs []byte
	need := -1
	for need < 0 || len(hs) < need {
		hdr := make([]byte, 5)
		if n, err := io.ReadFull(r, hdr); err != nil {
			return append(raw, hdr[:n]...), "", err
		}
		raw = append(raw, hdr...)
		if hdr[0] != 0x16 || hdr[1] != 0x03 {
			return raw, "", errNotTLS
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n == 0 || n > 1<<14+256 {
			return raw, "", errNotTLS
		}
		body := make([]byte, n)
		if m, err := io.ReadFull(r, body); err != nil {
			return append(raw, body[:m]...), "", err
		}
		raw = append(raw, body...)
		hs = append(hs, body...)
		if need < 0 && len(hs) >= 4 {
			if hs[0] != 0x01 {
				return raw, "", errNotTLS
			}
			need = 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if need > 64<<10 {
				return raw, "", errNotTLS
			}
		}
		if len(raw) > 70<<10 {
			return raw, "", errNotTLS
		}
	}
	return raw, parseSNI(hs[4:need]), nil
}

// parseSNI извлекает server_name из тела ClientHello.
func parseSNI(b []byte) string {
	if len(b) < 34 { // версия(2) + random(32)
		return ""
	}
	b = b[34:]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[i])
		}
		if len(b) < lenBytes+n {
			return false
		}
		b = b[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session_id, cipher_suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	total := int(binary.BigEndian.Uint16(b))
	ext := b[2:]
	if total < len(ext) {
		ext = ext[:total]
	}
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		n := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			return ""
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		if typ != 0 || len(data) < 2 {
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nl := int(binary.BigEndian.Uint16(list[1:]))
			if len(list) < 3+nl {
				return ""
			}
			if list[0] == 0 {
				return strings.ToLower(strings.TrimSuffix(string(list[3:3+nl]), "."))
			}
			list = list[3+nl:]
		}
	}
	return ""
}

// MatchSNI — совпадение домена или его поддомена (как в FPTN ALLOWED_SNI_LIST).
func MatchSNI(sni, pattern string) bool {
	pattern = strings.ToLower(strings.TrimPrefix(pattern, "*."))
	return sni == pattern || strings.HasSuffix(sni, "."+pattern)
}
