#!/bin/bash
# Installs (or updates) Ingress on macOS:
#
#   curl -fsSL https://raw.githubusercontent.com/azizbekatajanov/ingress/master/install.sh | bash
#
# Downloaded with curl, the app carries no "downloaded from the internet"
# mark, so macOS doesn't show the unverified-developer warning, and Ingress
# can update itself from then on. The archive is checked against the sha256
# in the release's update manifest. (That manifest is also ed25519-signed,
# but macOS has no built-in tool to check such a signature; Ingress itself
# checks it for every in-app update.)
set -euo pipefail

repo="azizbekatajanov/ingress"
dest="/Applications/Ingress.app"

[ "$(uname -s)" = "Darwin" ] || { echo "This installer is for macOS. On Linux, use the .deb or .tar.gz from https://github.com/$repo/releases"; exit 1; }
case "$(uname -m)" in
  arm64) platform="darwin/arm64" ;;
  x86_64) platform="darwin/amd64" ;;
  *) echo "Unsupported Mac: $(uname -m)"; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> Looking up the latest Ingress release"
curl -fsSL -o "$tmp/manifest.json" "https://github.com/$repo/releases/latest/download/ingress-update.json"
version=$(plutil -extract version raw -o - "$tmp/manifest.json")
url=$(plutil -extract "assets.$platform.url" raw -o - "$tmp/manifest.json")
sha=$(plutil -extract "assets.$platform.sha256" raw -o - "$tmp/manifest.json")
case "$url" in
  https://github.com/$repo/releases/download/*) ;;
  *) echo "Unexpected download address: $url"; exit 1 ;;
esac

echo "==> Downloading Ingress $version ($platform)"
curl -fSL --progress-bar -o "$tmp/Ingress.zip" "$url"
got=$(shasum -a 256 "$tmp/Ingress.zip" | cut -d' ' -f1)
[ "$got" = "$sha" ] || { echo "Checksum mismatch (expected $sha, got $got) — not installing."; exit 1; }

ditto -x -k "$tmp/Ingress.zip" "$tmp/unpacked"
app="$tmp/unpacked/Ingress.app"
codesign --verify --deep --strict "$app" || { echo "The app's code signature is broken — not installing."; exit 1; }

if pgrep -qf "Ingress.app/Contents/MacOS/ingress"; then
  echo "==> Ingress is running — asking it to quit (confirm in its window if it asks)"
  osascript -e 'tell application "Ingress" to quit' >/dev/null 2>&1 || true
  for _ in $(seq 1 120); do pgrep -qf "Ingress.app/Contents/MacOS/ingress" || break; sleep 0.5; done
  if pgrep -qf "Ingress.app/Contents/MacOS/ingress"; then echo "Ingress is still running. Quit it and run this again."; exit 1; fi
fi

echo "==> Installing to $dest"
sudo_cmd=""
[ -w /Applications ] && { [ ! -e "$dest" ] || [ -w "$dest" ]; } || sudo_cmd="sudo"
$sudo_cmd rm -rf "$dest.new"
$sudo_cmd ditto "$app" "$dest.new"
$sudo_cmd rm -rf "$dest"
$sudo_cmd mv "$dest.new" "$dest"

echo "==> Ingress $version installed"
open "$dest"
