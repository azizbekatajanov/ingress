package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Root side of component installation: hidden re-exec modes of this same
// binary, run elevated through elevatedRun (the same admin prompt used for
// connecting):
//
//	ingress --install-component <name> <archive.tar.gz>
//	ingress --remove-component <name>
//
// The caller has already verified the download, but that check ran
// unprivileged, so nothing it says is trusted here: the archive is read into
// memory once, its sha256 is recomputed and compared against this binary's
// own compiled-in manifest, and the same in-memory bytes are what gets
// extracted — no window between checking and using the file.
//
// Output protocol: exactly one final line, rootOKMarker or rootErrPrefix+msg,
// parsed by parseRootResult. Exit codes aren't relied on because
// AuthorizationExecuteWithPrivileges doesn't give us a reliable pid to wait on.

const (
	rootInstallFlag = "--install-component"
	rootRemoveFlag  = "--remove-component"
	rootOKMarker    = "INGRESS-RESULT: OK"
	rootErrPrefix   = "INGRESS-RESULT: ERROR: "

	// maxExtractedSize bounds the total unpacked size (zip-bomb guard).
	maxExtractedSize = 300 << 20
)

func isRootComponentCommand(arg string) bool {
	return arg == rootInstallFlag || arg == rootRemoveFlag
}

func runRootComponentCommand(cmd string, args []string) int {
	var err error
	switch cmd {
	case rootInstallFlag:
		err = rootInstall(args)
	case rootRemoveFlag:
		err = rootRemove(args)
	default:
		err = fmt.Errorf("unknown command %s", cmd)
	}
	if err != nil {
		fmt.Println(rootErrPrefix + strings.ReplaceAll(err.Error(), "\n", " "))
		return 1
	}
	fmt.Println(rootOKMarker)
	return 0
}

func rootInstall(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("установщик запущен без прав администратора")
	}
	if len(args) < 2 {
		return errors.New("usage: --install-component <name> <archive>")
	}
	name, archive := args[0], args[1]
	if _, ok := lookupComponent(name); !ok {
		return fmt.Errorf("неизвестный компонент %q", name)
	}
	manifest, err := rootManifest(args[2:])
	if err != nil {
		return err
	}
	build, ok := manifest[name][platformKey()]
	if !ok || build.SHA256 == "" {
		return fmt.Errorf("в манифесте нет сборки %s для %s", name, platformKey())
	}

	fi, err := os.Stat(archive)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxArchiveSize {
		return errors.New("архив недопустимого типа или размера")
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, build.SHA256) {
		return fmt.Errorf("контрольная сумма архива не совпадает с манифестом (%s)", got)
	}

	base := componentsBaseDir()
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return err
	}
	if err := ensureRootDir(base); err != nil {
		return err
	}
	if err := ensureRootDir(componentsDir()); err != nil {
		return err
	}

	return installArchive(data, name, build, componentsDir(), true)
}

// installArchive extracts data into compsDir/<name> via a staging directory
// and an atomic rename, so a failed install never leaves a half-written
// component behind and a running tunnel's binary is never modified in place.
// chownRoot is false only in tests (which can't chown to root).
func installArchive(data []byte, name string, build ComponentBuild, compsDir string, chownRoot bool) error {
	staging, err := os.MkdirTemp(compsDir, "."+name+".staging-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(staging)
		}
	}()

	if err := extractTarGz(data, staging); err != nil {
		return fmt.Errorf("распаковка: %w", err)
	}
	binFi, err := os.Lstat(filepath.Join(staging, "bin", name))
	if err != nil || !binFi.Mode().IsRegular() || binFi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("в архиве нет исполняемого bin/%s", name)
	}

	info, _ := json.MarshalIndent(installedInfo{
		Component:   name,
		Version:     build.Version,
		SHA256:      strings.ToLower(build.SHA256),
		InstalledAt: time.Now().UTC(),
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(staging, installedInfoFile), info, 0o644); err != nil {
		return err
	}
	if err := normalizeTree(staging, chownRoot); err != nil {
		return err
	}

	target := filepath.Join(compsDir, name)
	var old string
	if _, err := os.Lstat(target); err == nil {
		old = target + ".old-" + strconv.Itoa(os.Getpid())
		if err := os.Rename(target, old); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, target); err != nil {
		if old != "" {
			os.Rename(old, target)
		}
		return err
	}
	committed = true
	if old != "" {
		os.RemoveAll(old)
	}
	return nil
}

func rootRemove(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("удаление запущено без прав администратора")
	}
	if len(args) != 1 {
		return errors.New("usage: --remove-component <name>")
	}
	name := args[0]
	if _, ok := lookupComponent(name); !ok {
		return fmt.Errorf("неизвестный компонент %q", name)
	}
	target := componentDir(name)
	fi, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s не является каталогом", target)
	}
	return os.RemoveAll(target)
}

// ensureRootDir creates dir (0755) if missing, refuses symlinks/non-dirs,
// and forces root ownership + 0755 on whatever is there.
func ensureRootDir(dir string) error {
	fi, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s должен быть обычным каталогом", dir)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// extractTarGz unpacks regular files and directories only. Anything else
// (symlinks, hardlinks, devices) and any path escaping dest is rejected.
func extractTarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == "" || name == "." || name == "./" {
			continue
		}
		clean := path.Clean(name)
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("недопустимый путь в архиве: %q", hdr.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(clean))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, maxExtractedSize-total+1))
			f.Close()
			if err != nil {
				return err
			}
			total += n
			if total > maxExtractedSize {
				return errors.New("распакованный архив слишком большой")
			}
		case tar.TypeXGlobalHeader:
			continue
		default:
			return fmt.Errorf("неподдерживаемый тип записи %q в архиве (%s)", hdr.Typeflag, hdr.Name)
		}
	}
}

// normalizeTree makes everything under root owned by root:root/wheel, dirs
// 0755, files 0755 or 0644 — never group/other-writable, which is what
// verifyRootOwned checks before every run.
func normalizeTree(root string, chownRoot bool) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink in staging: %s", p)
		}
		if chownRoot {
			if err := os.Lchown(p, 0, 0); err != nil {
				return err
			}
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if d.IsDir() || fi.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		return os.Chmod(p, mode)
	})
}
