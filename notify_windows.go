package main

// systemNotify: not implemented on Windows yet (connecting isn't either —
// see elevate_windows.go).
func systemNotify(title, body string) {}
