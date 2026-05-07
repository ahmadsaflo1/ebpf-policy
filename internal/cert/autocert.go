package cert

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	AcmeLocalPebbleTestUrl    = "https://127.0.0.1:14000/dir"
	AcmeLetsencryptStagingUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
	AcmeLetsencryptUrl        = acme.LetsEncryptURL
	AcmeDigicertUrl           = "https://acme.digicert.com/v2/acme/directory"
	AcmeBuypassUrl            = "https://api.buypass.com/acme/directory"
)

type HostPolicy = autocert.HostPolicy

var (
	errHostNotAllowed = errors.New("host is not allowed")
)

func NewManager(certDir string, accountEmail, acmeDir string, hosts ...string) *autocert.Manager {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(certDir),
		Prompt:     autocert.AcceptTOS,
		Email:      accountEmail,
		HostPolicy: allowedHosts(hosts),
	}
	// default directory is letsencrypt production
	if acmeDir != "" {
		m.Client = &acme.Client{
			DirectoryURL: acmeDir,
		}
	}

	return m
}

func allowedHosts(hosts []string) autocert.HostPolicy {
	return (func(ctx context.Context, host string) error {
		if !IsHostname(host) {
			return errHostNotAllowed
		}

		for _, h := range hosts {
			// wildcarded host
			if h[0] == '*' && h[1] == '.' && strings.HasSuffix(h, host) {
				return nil
			} else if h == host {
				return nil
			}
		}
		return errHostNotAllowed
	})
}

// IsHostname validates hostname (domain name)
// <name> ::= <let>[*[<let-or-digit-or-hyphen>]<let-or-digit>]
// Hostnames are case insensitive so we accept capital letters.
func IsHostname(str string) bool {
	if len(str) == 0 {
		return false
	}
	if len(str) > 253 {
		return false
	}

	// only a letter as first char
	if r := str[0]; (r < 'a' || r > 'z') &&
		(r < 'A' || r > 'Z') {
		return false
	}
	// last char must be letter or digit
	if r := str[len(str)-1]; (r < 'a' || r > 'z') &&
		(r < 'A' || r > 'Z') &&
		(r < '0' || r > '9') {
		return false
	}

	dot := false
	var l rune
	var lp int
	for p, r := range str {

		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '-' && r != '.' {
			return false
		}

		if dot {
			// '..' and '.-' is not allowed
			if r == '.' || r == '-' {
				return false
			}
		}
		dot = r == '.'

		// each segment max 63 chars
		if !dot && p-lp >= 63 {
			return false
		}

		if dot {
			lp = p
			// '-.' is not allowed
			if l == '-' {
				return false
			}
		}
		l = r

	}
	return true
}
