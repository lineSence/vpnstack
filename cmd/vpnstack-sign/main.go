// vpnstack-sign — ключи и подпись релизов для OTA.
//
//	vpnstack-sign keygen            → печатает закрытый (секрет CI) и открытый ключ
//	vpnstack-sign sign FILE         → FILE.sig (ключ из VPNSTACK_SIGNING_KEY)
//	vpnstack-sign verify FILE PUB   → проверка
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vpnstack-sign keygen | sign FILE | verify FILE PUBKEY")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		fmt.Println("VPNSTACK_SIGNING_KEY (секрет GitHub Actions):", base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Println("VPNSTACK_PUBLIC_KEY  (переменная репозитория):", base64.StdEncoding.EncodeToString(pub))
	case "sign":
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("VPNSTACK_SIGNING_KEY")))
		if err != nil || len(seed) != ed25519.SeedSize {
			die("VPNSTACK_SIGNING_KEY не задан или некорректен")
		}
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			die(err.Error())
		}
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), b)
		if err := os.WriteFile(os.Args[2]+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
			die(err.Error())
		}
	case "verify":
		b, _ := os.ReadFile(os.Args[2])
		s, _ := os.ReadFile(os.Args[2] + ".sig")
		sig, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(s)))
		pub, _ := base64.StdEncoding.DecodeString(os.Args[3])
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, b, sig) {
			die("подпись НЕ верна")
		}
		fmt.Println("подпись верна")
	default:
		die("неизвестная команда")
	}
}

func die(s string) { fmt.Fprintln(os.Stderr, s); os.Exit(1) }
