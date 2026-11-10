// updatesign manages the ed25519 key that signs Ingress' update manifests.
//
//	go run ./tools/updatesign keygen          create the key in the login keychain, print the public key
//	go run ./tools/updatesign pubkey          print the public key (for updater.go)
//	go run ./tools/updatesign sign FILE       write FILE.sig (base64 signature of FILE's exact bytes)
//	go run ./tools/updatesign verify FILE PUB check FILE.sig against a base64 public key
//
// The private key (its 32-byte seed, base64) lives only in the macOS login
// keychain, item "ingress-update-signing". Back it up: without it no
// installed Ingress will accept another update. To back up:
//
//	security find-generic-password -s ingress-update-signing -w
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	keychainService = "ingress-update-signing"
	keychainAccount = "ingress"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "updatesign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: updatesign keygen | pubkey | sign FILE | verify FILE PUBKEY")
	}
	switch args[0] {
	case "keygen":
		if _, err := loadKey(); err == nil {
			return errors.New("a key already exists in the keychain; refusing to overwrite it")
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		seed := base64.StdEncoding.EncodeToString(priv.Seed())
		if out, err := exec.Command("security", "add-generic-password", "-a", keychainAccount, "-s", keychainService,
			"-l", "Ingress update signing key", "-w", seed).CombinedOutput(); err != nil {
			return fmt.Errorf("keychain: %v %s", err, out)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	case "pubkey":
		priv, err := loadKey()
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	case "sign":
		if len(args) != 2 {
			return errors.New("usage: updatesign sign FILE")
		}
		priv, err := loadKey()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
		return os.WriteFile(args[1]+".sig", []byte(sig+"\n"), 0o644)
	case "verify":
		if len(args) != 3 {
			return errors.New("usage: updatesign verify FILE PUBKEY")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(args[1] + ".sig")
		if err != nil {
			return err
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(args[2])
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("bad public key")
		}
		if !ed25519.Verify(pub, data, sig) {
			return errors.New("signature does NOT match")
		}
		fmt.Println("signature OK")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

func loadKey() (ed25519.PrivateKey, error) {
	out, err := exec.Command("security", "find-generic-password", "-a", keychainAccount, "-s", keychainService, "-w").Output()
	if err != nil {
		return nil, errors.New("no signing key in the keychain (run: updatesign keygen)")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the keychain item doesn't hold a valid key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
