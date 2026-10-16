package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPSVerificationFamilyAndResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trust bool
		code  int
		body  string
		want  string
	}{{"valid", true, 204, "", "PASS"}, {"untrusted", false, 204, "", "FAIL"}, {"redirect", true, 302, "", "FAIL"}, {"unexpected body", true, 200, "secret body", "FAIL"}} {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if tc.code == 302 {
					w.Header().Set("Location", "/redirect?credential=not-for-output")
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.StartTLS()
			defer s.Close()
			c := Defaults()
			c.HTTPS.URL = s.URL
			if tc.code == 200 {
				c.HTTPS.Status = 200
			}
			e := NewEngine(c)
			if tc.trust {
				roots := x509.NewCertPool()
				roots.AddCert(s.Certificate())
				e.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			}
			requested := ""
			e.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				requested = network
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := e.https(ctx, job{id: "https", version: 4})
			d := r.Details.(HTTPSDetails)
			if r.Status != tc.want || requested != "tcp4" {
				t.Fatal(r, requested)
			}
			if tc.trust && (!d.CertificateVerified || d.CertificateExpiry == nil) {
				t.Fatal(d)
			}
			if tc.code == 302 && (hits != 1 || d.RedirectLocation == "" || d.RedirectLocation == "/redirect?credential=not-for-output") {
				t.Fatal("redirect followed or leaked", d, hits)
			}
		})
	}
}
func TestHTTPSIPv6NeverFallsBackOrUsesProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	e := NewEngine(Defaults())
	called := 0
	e.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		called++
		if network != "tcp6" {
			t.Fatalf("fallback: %s", network)
		}
		return nil, errors.New("fixture: IPv6 unreachable")
	}
	r := e.https(context.Background(), job{id: "https", version: 6})
	if r.Status != "FAIL" || called != 1 {
		t.Fatal(r, called)
	}
}
func TestHTTPSDeadline(t *testing.T) {
	e := NewEngine(Defaults())
	e.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := e.https(ctx, job{id: "https", version: 4})
	if r.Status != "FAIL" || time.Since(start) > time.Second {
		t.Fatal(r)
	}
}
