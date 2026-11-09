//go:build darwin

package main

// componentsBaseDir is where Ingress installs its own VPN binaries. It's a
// system-wide, root-owned location on purpose: the binaries run as root, so
// they must not live anywhere the user (or anything running as the user)
// can write.
func componentsBaseDir() string { return "/Library/Application Support/Ingress" }
