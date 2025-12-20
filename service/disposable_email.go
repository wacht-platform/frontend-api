package service

import (
	"bufio"
	"embed"
	"strings"
)

//go:embed disposable_email_blocklist.conf
var disposableEmailFile embed.FS

var disposableDomains = make(map[string]struct{}, 5000)

func init() {
	f, err := disposableEmailFile.Open("disposable_email_blocklist.conf")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			disposableDomains[domain] = struct{}{}
		}
	}
}

func IsDisposableEmailDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domainParts := strings.Split(strings.ToLower(parts[1]), ".")
	for i := 0; i < len(domainParts)-1; i++ {
		domain := strings.Join(domainParts[i:], ".")
		if _, ok := disposableDomains[domain]; ok {
			return true
		}
	}
	return false
}
