package check

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"
)

type HTTPSDetails struct {
	RemoteAddress       string     `json:"remote_address"`
	DNSMS               *float64   `json:"dns_ms"`
	TCPMS               *float64   `json:"tcp_ms"`
	TLSMS               *float64   `json:"tls_ms"`
	HTTPMS              *float64   `json:"http_ms"`
	TLSVersion          uint16     `json:"tls_version"`
	CertificateVerified bool       `json:"certificate_verified"`
	CertificateExpiry   *time.Time `json:"certificate_expiry"`
	StatusCode          int        `json:"status_code"`
	RedirectLocation    string     `json:"redirect_location,omitempty"`
	BodyEmpty           *bool      `json:"body_empty"`
	FailureStage        string     `json:"failure_stage,omitempty"`
}

func (e *Engine) https(ctx context.Context, j job) Result {
	r := Result{Check: j.id, Target: e.Config.HTTPS.URL, IPVersion: j.version, Status: "FAIL"}
	d := HTTPSDetails{FailureStage: "DNS/TCP"}
	var mu sync.Mutex
	var dnsStart, tcpStart, tlsStart, httpStart time.Time
	ms := func(t time.Time) *float64 { v := float64(time.Since(t)) / float64(time.Millisecond); return &v }
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			mu.Lock()
			defer mu.Unlock()
			dnsStart = time.Now()
			d.FailureStage = "DNS"
		},
		DNSDone:           func(httptrace.DNSDoneInfo) { mu.Lock(); defer mu.Unlock(); d.DNSMS = ms(dnsStart) },
		ConnectStart:      func(string, string) { mu.Lock(); defer mu.Unlock(); tcpStart = time.Now(); d.FailureStage = "TCP" },
		ConnectDone:       func(_, _ string, err error) { mu.Lock(); defer mu.Unlock(); d.TCPMS = ms(tcpStart) },
		TLSHandshakeStart: func() { mu.Lock(); defer mu.Unlock(); tlsStart = time.Now(); d.FailureStage = "TLS" },
		TLSHandshakeDone: func(s tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			d.TLSMS = ms(tlsStart)
			d.TLSVersion = s.Version
			d.CertificateVerified = err == nil && len(s.VerifiedChains) > 0
			if len(s.PeerCertificates) > 0 {
				v := s.PeerCertificates[0].NotAfter
				d.CertificateExpiry = &v
			}
		},
		GotConn: func(i httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			d.RemoteAddress = i.Conn.RemoteAddr().String()
			d.FailureStage = "HTTP"
			httpStart = time.Now()
		},
		GotFirstResponseByte: func() { mu.Lock(); defer mu.Unlock(); d.HTTPMS = ms(httpStart) },
	}
	dial := e.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: e.TLSConfig, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dial(ctx, "tcp"+strconv.Itoa(j.version), addr)
	}, TLSHandshakeTimeout: time.Duration(e.Config.HTTPS.TimeoutSeconds) * time.Second, MaxResponseHeaderBytes: 65536, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, e.Config.HTTPS.URL, nil)
	if err != nil {
		r.Status = "ERROR"
		r.Reason = "HTTPSリクエスト生成失敗"
		return r
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Reason = "HTTPS接続失敗: " + err.Error()
	} else {
		defer resp.Body.Close()
		mu.Lock()
		d.StatusCode = resp.StatusCode
		// Retain only origin/path; redirect queries can contain credentials.
		if u, err := resp.Location(); err == nil {
			u.User = nil
			u.RawQuery = ""
			u.Fragment = ""
			d.RedirectLocation = u.String()
		}
		mu.Unlock()
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1))
		empty := len(b) == 0
		mu.Lock()
		d.BodyEmpty = &empty
		mu.Unlock()
		switch {
		case readErr != nil:
			r.Reason = "HTTP本文の有無を確認できません"
		case resp.StatusCode != e.Config.HTTPS.Status:
			r.Reason = "期待外のHTTPステータス（ポータル等の可能性、原因未確定）"
		case e.Config.HTTPS.EmptyBody && !empty:
			r.Reason = "空の本文を期待しましたが本文があります"
		default:
			r.Status = "PASS"
			r.Reason = "経路固定・証明書検証・HTTPS応答条件を確認"
			mu.Lock()
			d.FailureStage = ""
			mu.Unlock()
		}
	}
	mu.Lock()
	r.Details = d
	mu.Unlock()
	return r
}
