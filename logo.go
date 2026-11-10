package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const logoSize = 128

// logosDir is where per-profile logos live: <config dir>/ingress/logos/<profile id>.png.
// Only the file's existence matters (Profile.Logo is a flag), so profiles.json
// stays small and the logo survives the original file being moved or deleted.
func logosDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, "ingress", "logos")
	return d, os.MkdirAll(d, 0o700)
}

func logoPath(profileID string) (string, error) {
	d, err := logosDir()
	if err != nil {
		return "", err
	}
	// Profile IDs are generated ("p"+timestamp) but come back over the
	// frontend bridge, so never let one escape the logos directory.
	return filepath.Join(d, filepath.Base(profileID)+".png"), nil
}

// squareThumb center-crops src to a square and box-averages it down to
// size x size (never upscales past the source's own resolution).
func squareThumb(src image.Image, size int) *image.RGBA {
	b := src.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	x0 := b.Min.X + (b.Dx()-side)/2
	y0 := b.Min.Y + (b.Dy()-side)/2
	out := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		sy0 := y0 + y*side/size
		sy1 := y0 + (y+1)*side/size
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for x := 0; x < size; x++ {
			sx0 := x0 + x*side/size
			sx1 := x0 + (x+1)*side/size
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var r, g, bl, a, n uint64
			for sy := sy0; sy < sy1; sy++ {
				for sx := sx0; sx < sx1; sx++ {
					pr, pg, pb, pa := src.At(sx, sy).RGBA()
					r += uint64(pr)
					g += uint64(pg)
					bl += uint64(pb)
					a += uint64(pa)
					n++
				}
			}
			out.Set(x, y, color.RGBA64{uint16(r / n), uint16(g / n), uint16(bl / n), uint16(a / n)})
		}
	}
	return out
}

func saveLogo(profileID, srcPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return fmt.Errorf("%s: %w", T("logo.err.read"), err)
	}
	// Flatten onto transparent RGBA so premultiplied alpha survives the resize.
	rgba := image.NewRGBA(img.Bounds())
	draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Src)
	size := logoSize
	if w, h := img.Bounds().Dx(), img.Bounds().Dy(); w < size || h < size {
		size = w
		if h < size {
			size = h
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, squareThumb(rgba, size)); err != nil {
		return err
	}
	dst, err := logoPath(profileID)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, buf.Bytes(), 0o600)
}

func loadLogoDataURL(profileID string) string {
	p, err := logoPath(profileID)
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func deleteLogo(profileID string) {
	if p, err := logoPath(profileID); err == nil {
		_ = os.Remove(p)
	}
}

// --- Wails-bound methods ---

// PickProfileLogo opens an image picker and stores the chosen file as the
// profile's logo. Returns the updated profile, or the unchanged one if the
// dialog was cancelled.
func (a *App) PickProfileLogo(profileID string) (Profile, error) {
	p, ok := a.store.Get(profileID)
	if !ok {
		return Profile{}, os.ErrNotExist
	}
	path, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: T("logo.pick_title"),
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: T("logo.filter"), Pattern: "*.png;*.jpg;*.jpeg;*.gif"},
		},
	})
	if err != nil || path == "" {
		return p, err
	}
	if err := saveLogo(profileID, path); err != nil {
		return p, err
	}
	return a.store.SetLogo(profileID, true)
}

func (a *App) RemoveProfileLogo(profileID string) (Profile, error) {
	deleteLogo(profileID)
	return a.store.SetLogo(profileID, false)
}

// GetProfileLogos returns profileID -> data URL for every profile that has one.
func (a *App) GetProfileLogos() map[string]string {
	out := map[string]string{}
	for _, p := range a.store.List() {
		if p.Logo {
			if u := loadLogoDataURL(p.ID); u != "" {
				out[p.ID] = u
			}
		}
	}
	return out
}

func (a *App) GetProfileLogo(profileID string) string {
	return loadLogoDataURL(profileID)
}
