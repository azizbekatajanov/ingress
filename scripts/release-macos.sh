#!/usr/bin/env bash
# scripts/release-macos.sh — builds everything a release needs from macOS:
#
#   dist/Ingress-<v>-arm64.dmg, dist/Ingress-<v>-intel.dmg   (people)
#   dist/Ingress-<v>-darwin-arm64.zip, …-darwin-amd64.zip     (in-app updates, install.sh)
#   dist/ingress-update.json + .sig                           (signed update manifest)
#
# The manifest is signed with the key in the login keychain (tools/updatesign);
# the script refuses to finish if the signature doesn't verify against the
# public key compiled into this very build. Upload everything in dist/ to the
# GitHub release v<v>; Linux/Windows assets come from CI as before.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^[[:space:]]*AppVersion[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' version.go)
plist_version=$(sed -n 's/.*"productVersion": "\(.*\)".*/\1/p' wails.json)
[ "$version" = "$plist_version" ] || { echo "version.go ($version) != wails.json ($plist_version)"; exit 1; }
base="https://github.com/azizbekatajanov/ingress/releases/download/v$version"
dist=dist; rm -rf "$dist"; mkdir -p "$dist"

assets=""
for arch in arm64 amd64; do
  label=$([ $arch = arm64 ] && echo arm64 || echo intel)
  echo "==> build darwin/$arch"
  wails build -clean -platform "darwin/$arch" >/dev/null
  app=build/bin/Ingress.app
  [ "$(lipo -archs $app/Contents/MacOS/ingress)" = "$([ $arch = arm64 ] && echo arm64 || echo x86_64)" ] || { echo "wrong arch"; exit 1; }
  codesign --verify --deep --strict "$app"

  zip="Ingress-$version-darwin-$arch.zip"
  ditto -c -k --keepParent "$app" "$dist/$zip"

  stage=$(mktemp -d); cp -R "$app" "$stage/"; ln -s /Applications "$stage/Applications"
  hdiutil create -quiet -volname Ingress -srcfolder "$stage" -format UDZO -ov "$dist/Ingress-$version-$label.dmg"
  rm -rf "$stage"

  sum=$(shasum -a 256 "$dist/$zip" | cut -d' ' -f1)
  size=$(stat -f %z "$dist/$zip")
  assets="$assets${assets:+,}
    \"darwin/$arch\": {\"url\": \"$base/$zip\", \"sha256\": \"$sum\", \"size\": $size}"
done

cat > "$dist/ingress-update.json" <<JSON
{
  "version": "$version",
  "notesUrl": "https://github.com/azizbekatajanov/ingress/releases/tag/v$version",
  "assets": {$assets
  }
}
JSON
go run ./tools/updatesign sign "$dist/ingress-update.json"
pub=$(sed -n 's/^var updatePublicKey = "\(.*\)"/\1/p' updater.go)
go run ./tools/updatesign verify "$dist/ingress-update.json" "$pub"
(cd "$dist" && shasum -a 256 ./*.dmg ./*.zip > SHA256SUMS-macos.txt)
ls -la "$dist"
