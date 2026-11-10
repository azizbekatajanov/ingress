package main

import (
	"syscall"
	"unsafe"
)

// GetUserDefaultLocaleName gives "ru-RU", "uz-Latn-UZ"…
func systemLanguages() []string {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); r == 0 {
		return envLanguages()
	}
	return append([]string{syscall.UTF16ToString(buf)}, envLanguages()...)
}
