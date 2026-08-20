package main

// AppVersion and AppAuthor are the single source of truth for the in-app
// About screen. Keep AppVersion in sync with wails.json's info.productVersion
// (which drives the native macOS "About Ingress" menu item and Info.plist) —
// there's no build-time wiring between the two, so both are hand-maintained.
const (
	AppVersion = "1.0.0"
	AppAuthor  = "Azizbek Atajanov"
)

// AppInfo is what the frontend's About screen renders.
type AppInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Author  string `json:"author"`
}

func (a *App) GetAppInfo() AppInfo {
	return AppInfo{Name: "Ingress", Version: AppVersion, Author: AppAuthor}
}
