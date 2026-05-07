package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ahmadsaflo1/ebpf-policy/internal/cert"
	"github.com/ahmadsaflo1/ebpf-policy/internal/config"
)

type server struct {
	conf *config.Settings
	dir  fs.FS
}

func Start(ctx context.Context, conf *config.Settings) (*http.Server, error) {
	s := &server{
		conf: conf,
		dir:  os.DirFS(conf.Server.WebDir),
	}

	var handler http.Handler = s

	addr := conf.Server.Host + ":" + strconv.Itoa(conf.Server.Port)

	if conf.Server.LetsEncrypt {
		certDir := conf.Server.CertDir
		if certDir == "" {
			certDir = filepath.Join(conf.AppDir, "certs")
		}

		// by default we are using letsencrypt staging certificates
		acmeDir := cert.AcmeLetsencryptStagingUrl
		if conf.Env == "prod" {
			acmeDir = cert.AcmeLetsencryptUrl
		}
		manager := cert.NewManager(certDir, conf.Server.Contact, acmeDir)

		manager.HostPolicy = allowedHost(conf.Server.Domains)
		tlsConf := manager.TLSConfig()
		tlsConf.CipherSuites = config.DefaultCiphers
		tlsConf.CurvePreferences = config.DefaultCurves
		tlsConf.MinVersion = tls.VersionTLS12
		tlsConf.MaxVersion = tls.VersionTLS13

		altAddr := conf.Server.Host + ":" + strconv.Itoa(conf.Server.AltPort)
		go func() {
			// http listener for acme-http-challenges and a http fallback that redirects to https
			handler := manager.HTTPHandler(httpsRedirector(443))

			if err := http.ListenAndServe(altAddr, handler); err != nil {
				slog.Error("http fallback listener", "error", err)
			}

		}()

		srv := &http.Server{
			Addr:    addr,
			Handler: handler,
		}

		slog.Info("server", "listener", addr)
		srv.TLSConfig = tlsConf
		go srv.ListenAndServeTLS("", "")

		return srv, nil
	}

	// HTTP mode server
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go srv.ListenAndServe()

	return srv, nil
}

var (
	errHostNotAllowed = errors.New("hostname not whitelisted")
	errHostInvalid    = errors.New("hostname is invalid")
)

func allowedHost(hosts []string) cert.HostPolicy {
	return func(_ context.Context, hostName string) error {
		if len(hostName) == 0 {
			return errHostInvalid
		}

		for _, h := range hosts {
			if len(h) > 0 && h[0] == '*' {
				p := 1
				if len(h) > 1 && h[1] == '.' {
					p = 2
				}
				if strings.HasSuffix(hostName, h[p:]) {
					return nil
				}
			} else if h == hostName {
				return nil
			}
		}

		return errHostNotAllowed
	}
}

func httpsRedirector(destPort int) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := &url.URL{
			Scheme:   "https",
			User:     r.URL.User,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Fragment: r.URL.Fragment,
		}
		if destPort != 443 {
			if p := strings.Index(u.Host, ":"); p > 0 {
				u.Host = u.Host[0:p] + ":" + strconv.Itoa(destPort)
			} else {
				u.Host += ":" + strconv.Itoa(destPort)
			}
		}

		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
	})
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// User agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15
	// agent => 'Safari/605.1.15'

	remote, _, _ := net.SplitHostPort(req.RemoteAddr)
	ip := net.ParseIP(remote)

	log := slog.With(
		"host", req.Host,
		"ip", ip,
		"ref", req.Referer(),
		"path", req.RequestURI,
		"agent", req.UserAgent(),
	)

	// in your handlers use
	// log := LogContext(r.Context())
	r := req.WithContext(NewLogContext(req.Context(), log))

	// log the request
	log.Info(r.Method)

	// if we get a panic attack, report it
	defer crashReport(w, r)

	// serve some nice content
	http.ServeFileFS(w, r, s.dir, r.URL.Path)
}

type logContext struct{}

// NewLogContext returns a context that contains the given Logger.
// Use FromContext to retrieve the Logger.
func NewLogContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, logContext{}, l)
}

// LogContext returns the Logger stored in ctx by NewLogContext,
// or it returns the default Logger if not found.
func LogContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(logContext{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// crashReport recovers a crash(panic) and reports the fault
func crashReport(w http.ResponseWriter, r *http.Request) {
	if e := recover(); e != nil {
		log := LogContext(r.Context())

		eStr := ""
		switch e := e.(type) {
		case string:
			eStr = e
		case runtime.Error:
			eStr = e.Error()
		case error:
			if e == http.ErrAbortHandler {
				return
			}
			eStr = e.Error()
		default:
			eStr = fmt.Sprintf("%s", e)
		}
		log.Error("recover", "error", eStr)
		stackTrace := (func() []byte {
			buf := make([]byte, 1024)
			for {
				n := runtime.Stack(buf, false)
				if n < len(buf) {
					return buf[:n]
				}
				buf = make([]byte, 2*len(buf))
			}
		}())

		// NOTE: grabs lines after the "runtime/panic.go ... \n"
		if i := bytes.LastIndex(stackTrace, []byte("runtime/panic.go")); i > 0 {
			if j := bytes.IndexByte(stackTrace[i:], '\n'); j > 0 {
				stackTrace = stackTrace[i+j+1:]
			}
		}
		os.Stderr.Write(stackTrace)

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("oups, I crashed!"))

		return
	}
}
