package main

import "os/exec"

// systemNotify shows a desktop notification via notify-send (libnotify),
// when it's installed.
func systemNotify(title, body string) {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return
	}
	go func() { _ = exec.Command(path, "--app-name=Ingress", "--", title, body).Run() }()
}
