#!/bin/sh
# On purge, remove the VPN clients Ingress installed itself (root-owned, see
# components_paths_linux.go). A plain remove keeps them, like config files,
# so reinstalling doesn't need another download + admin prompt.
set -e

if [ "$1" = "purge" ]; then
    rm -rf /opt/ingress
fi

exit 0
