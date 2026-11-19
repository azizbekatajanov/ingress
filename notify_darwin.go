package main

import "os/exec"

// systemNotify shows a macOS notification. The texts go in as osascript
// arguments, never into the script source, so nothing in them is executed.
func systemNotify(title, body string) {
	go func() {
		_ = exec.Command("osascript",
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			title, body).Run()
	}()
}
