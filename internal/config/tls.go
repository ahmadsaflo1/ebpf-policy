package config

import "crypto/tls"

// Recommended "secure" TLS1.3, TLS1.2 ciphersuites at time of writing
// NOTE: That this can affect price/perfomance of running the server
// revisit and add/remove ciphers when browser support changes.
var DefaultCiphers = []uint16{
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// Curves in order of fast and "secure"
// TODO: add support for EdDSA and goldilocks(P-448) curves when available
var DefaultCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP521,
	tls.CurveP256,
	tls.CurveP384,
}
