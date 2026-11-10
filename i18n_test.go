package main

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// Existing tests assert the Russian wording they were written against.
func TestMain(m *testing.M) {
	setLanguage("ru")
	os.Exit(m.Run())
}

// Every language has every key, with the same placeholders.
func TestCatalogsComplete(t *testing.T) {
	cats := loadCatalogs()
	ph := regexp.MustCompile(`\{\d+\}`)
	placeholders := func(s string) []string {
		p := ph.FindAllString(s, -1)
		sort.Strings(p)
		return p
	}
	for key, en := range cats["en"] {
		for _, lang := range supportedLanguages[1:] {
			v, ok := cats[lang][key]
			if !ok {
				t.Errorf("%s: missing %q", lang, key)
				continue
			}
			if !reflect.DeepEqual(placeholders(en), placeholders(v)) {
				t.Errorf("%s %q: placeholders %v, en has %v", lang, key, placeholders(v), placeholders(en))
			}
		}
	}
	for _, lang := range supportedLanguages[1:] {
		for key := range cats[lang] {
			if _, ok := cats["en"][key]; !ok {
				t.Errorf("%s has %q, en doesn't", lang, key)
			}
		}
	}
}

func TestMatchLanguage(t *testing.T) {
	cases := []struct {
		prefs []string
		want  string
	}{
		{[]string{"ru-UZ", "en-US"}, "ru"},
		{[]string{"uz-Latn-UZ"}, "uz"},
		{[]string{"uz_UZ.UTF-8"}, "uz"},
		{[]string{"de-DE", "ru-RU"}, "en"}, // first preference unsupported → English
	}
	for _, c := range cases {
		if got := matchLanguage(c.prefs); got != c.want {
			t.Errorf("matchLanguage(%v) = %s, want %s", c.prefs, got, c.want)
		}
	}
	if got := matchLanguage([]string{"C", "", "ru_RU.UTF-8"}); got != "ru" {
		t.Errorf("C locale should be skipped, got %s", got)
	}
	if got := matchLanguage(nil); got != "en" {
		t.Errorf("empty → %s", got)
	}
}

func TestTPlaceholdersAndFallback(t *testing.T) {
	if got := TL("en", "log.connecting", "vpn.example.com"); got != "Connecting to vpn.example.com..." {
		t.Errorf("en: %q", got)
	}
	if got := TL("uz", "log.connecting", "vpn.example.com"); got != "vpn.example.com ga ulanilmoqda..." {
		t.Errorf("uz: %q", got)
	}
	if got := TL("ru", "no.such.key"); got != "no.such.key" {
		t.Errorf("missing key: %q", got)
	}
}

func TestLangArgRoundTrip(t *testing.T) {
	defer setLanguage("ru")
	setLanguage("uz")
	args := []string{"openconnect", "/tmp/x.tar.gz", langArg()}
	setLanguage("en")
	rest := takeLangArg(args)
	if language() != "uz" || len(rest) != 2 {
		t.Errorf("lang=%s rest=%v", language(), rest)
	}
}
