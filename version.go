package main

// AppVersion and AppAuthor are the single source of truth for the in-app
// About screen (and the "About Ingress" native menu item in main.go, which
// opens that same screen rather than a native panel). Keep AppVersion in
// sync with wails.json's info.productVersion (which drives Info.plist) —
// there's no build-time wiring between the two, so both are hand-maintained.
const (
	AppVersion   = "1.0.4"
	AppAuthor    = "Azizbek Atajanov"
	AppGithubURL = "https://github.com/azizbekatajanov/ingress"
)

// AppInfo is what the frontend's About screen renders.
type AppInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Author    string `json:"author"`
	GithubURL string `json:"githubUrl"`
}

func (a *App) GetAppInfo() AppInfo {
	return AppInfo{Name: "Ingress", Version: AppVersion, Author: AppAuthor, GithubURL: AppGithubURL}
}
