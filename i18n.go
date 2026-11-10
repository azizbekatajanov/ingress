package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// User-facing text in three languages. Every string Ingress itself shows
// (UI, tray, errors, its own log lines) lives in i18n/<lang>.json under a
// flat key; the frontend gets the same catalog through App.GetI18n, so
// there's one source of truth. Output of the VPN clients themselves is
// never translated.
//
// Placeholders are positional, {0} {1}…, so a translation can reorder them.
// Missing keys fall back to English, then to the key itself.

//go:embed i18n/*.json
var i18nFS embed.FS

// supportedLanguages, in the order the language picker shows them.
var supportedLanguages = []string{"en", "ru", "uz"}

const defaultLanguage = "en"

var (
	i18nOnce     sync.Once
	i18nCatalogs map[string]map[string]string

	langMu      sync.RWMutex
	currentLang = defaultLanguage
)

func loadCatalogs() map[string]map[string]string {
	i18nOnce.Do(func() {
		i18nCatalogs = make(map[string]map[string]string)
		for _, lang := range supportedLanguages {
			data, err := i18nFS.ReadFile("i18n/" + lang + ".json")
			if err != nil {
				panic(fmt.Sprintf("i18n: missing catalog %s: %v", lang, err))
			}
			m := make(map[string]string)
			if err := json.Unmarshal(data, &m); err != nil {
				panic(fmt.Sprintf("i18n: bad catalog %s: %v", lang, err))
			}
			i18nCatalogs[lang] = m
		}
	})
	return i18nCatalogs
}

// language returns the language currently in effect.
func language() string {
	langMu.RLock()
	defer langMu.RUnlock()
	return currentLang
}

// setLanguage switches the language in effect; an unsupported code is
// ignored.
func setLanguage(lang string) {
	if !isSupportedLanguage(lang) {
		return
	}
	langMu.Lock()
	currentLang = lang
	langMu.Unlock()
}

func isSupportedLanguage(lang string) bool {
	for _, l := range supportedLanguages {
		if l == lang {
			return true
		}
	}
	return false
}

// resolveLanguage turns the saved setting ("" = follow the system) into
// the language to use.
func resolveLanguage(setting string) string {
	if isSupportedLanguage(setting) {
		return setting
	}
	return matchLanguage(systemLanguages())
}

// matchLanguage picks the first supported language from a preference list
// of locale tags ("ru-RU", "uz_UZ.UTF-8", "uz-Latn-UZ", "en"…). Uzbek in
// Cyrillic script is still "uz": it's the only Uzbek we have.
func matchLanguage(prefs []string) string {
	for _, p := range prefs {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || p == "c" || p == "posix" {
			continue
		}
		base := p
		if i := strings.IndexAny(base, "-_.@"); i >= 0 {
			base = base[:i]
		}
		if isSupportedLanguage(base) {
			return base
		}
		// The first real preference wins even if unsupported: someone with
		// German first and Russian second gets English, not Russian.
		return defaultLanguage
	}
	return defaultLanguage
}

// envLanguages reads the POSIX locale variables in priority order.
func envLanguages() []string {
	var out []string
	if v := os.Getenv("LANGUAGE"); v != "" {
		out = append(out, strings.Split(v, ":")...)
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, v)
		}
	}
	return out
}

var placeholderRe = regexp.MustCompile(`\{(\d+)\}`)

// T returns the text for key in the current language with {0}, {1}…
// replaced by args.
func T(key string, args ...any) string {
	return TL(language(), key, args...)
}

// TL is T for an explicit language.
func TL(lang, key string, args ...any) string {
	cats := loadCatalogs()
	s, ok := cats[lang][key]
	if !ok {
		if s, ok = cats[defaultLanguage][key]; !ok {
			s = key
		}
	}
	if len(args) == 0 {
		return s
	}
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		var i int
		fmt.Sscanf(m, "{%d}", &i)
		if i < len(args) {
			return fmt.Sprint(args[i])
		}
		return m
	})
}

// i18nBundle is what the frontend gets.
type i18nBundle struct {
	Language  string            `json:"language"`       // in effect
	Setting   string            `json:"setting"`        // saved choice; "" = system
	System    string            `json:"systemLanguage"` // what "" would pick
	Languages []string          `json:"languages"`      // picker order
	Strings   map[string]string `json:"strings"`        // the catalog, English-filled
}

func bundleFor(lang, setting string) i18nBundle {
	cats := loadCatalogs()
	merged := make(map[string]string, len(cats[defaultLanguage]))
	for k, v := range cats[defaultLanguage] {
		merged[k] = v
	}
	for k, v := range cats[lang] {
		merged[k] = v
	}
	return i18nBundle{Language: lang, Setting: setting, System: matchLanguage(systemLanguages()), Languages: supportedLanguages, Strings: merged}
}

// langArg is appended to argv of Ingress' own child processes (root
// installer, SAML window) so their messages come out in the same language.
const langArgPrefix = "--lang="

func langArg() string { return langArgPrefix + language() }

// takeLangArg removes a trailing --lang=xx from args and applies it.
func takeLangArg(args []string) []string {
	if n := len(args); n > 0 && strings.HasPrefix(args[n-1], langArgPrefix) {
		setLanguage(strings.TrimPrefix(args[n-1], langArgPrefix))
		return args[:n-1]
	}
	return args
}
