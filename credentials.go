package main

import "github.com/zalando/go-keyring"

// Credentials stores VPN profile passwords in the OS-native secure store
// (Keychain on macOS, Credential Manager on Windows, Secret Service/libsecret on Linux)
// instead of profiles.json, so the user isn't re-prompted on every connect.
const keyringService = "ingress"

func SavePassword(profileID, password string) error {
	if password == "" {
		return DeletePassword(profileID)
	}
	return keyring.Set(keyringService, profileID, password)
}

func LoadPassword(profileID string) (string, error) {
	pw, err := keyring.Get(keyringService, profileID)
	if err == keyring.ErrNotFound {
		return "", nil
	}
	return pw, err
}

func DeletePassword(profileID string) error {
	err := keyring.Delete(keyringService, profileID)
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}
