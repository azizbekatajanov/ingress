#!/bin/sh
# Refreshes the desktop entry / icon caches so Ingress shows up in the
# application menu immediately, without requiring a logout. Best-effort:
# these tools are near-universal on a desktop install, but this must never
# fail the package install if one happens to be missing (a minimal/headless
# system, a distro that names the icon cache tool differently, etc).
set -e

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi

exit 0
