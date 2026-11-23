package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

type resolver interface { LookupIPAddr(context.Context, string) ([]net.IPAddr, error) }
type systemResolver struct{}
func (systemResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) { return net.DefaultResolver.LookupIPAddr(ctx, host) }

type gateway struct { token string; resolver resolver; clientFactory func(host string, ip net.IP) *http.Client }

type fetchRequest struct { URL string `json:"url"` }
type fetchResponse struct { Status int `json:"status"`; Header map[string]string `json:"headers"`; Body []byte `json:"body"` }

func publicIP(ip net.IP) bool {
	if ip == nil { return false }
	if v4 := ip.To4(); v4 != nil {
		a := v4[0]
		if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
		if a == 169 && v4[1] == 254 { return false }
		if a == 172 && v4[1] >= 16 && v4[1] <= 31 { return false }
		if a == 192 && v4[1] == 168 { return false }
		if a == 100 && v4[1] >= 64 && v4[1] <= 127 { return false }
		if a == 192 && v4[1] == 0 && (v4[2] == 0 || v4[2] == 2) { return false }
		if a == 192 && v4[1] == 88 && v4[2] == 99 { return false }
		if a == 198 && (v4[1] == 18 || v4[1] == 19 || (v4[1] == 51 && v4[2] == 100)) { return false }
		if a == 203 && v4[1] == 0 && (v4[2] == 113 || v4[2] == 0) { return false }
		return true
	}
	v6 := ip.To16()
	if v6 == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() { return false }
	// Only global-unicast 2000::/3, excluding documentation, transition and special-use blocks.
	p, _ := netip.ParseAddr(v6.String())
	if !p.IsValid() || !p.IsGlobalUnicast() || p.IsPrivate() { return false }
	b := v6
	if b[0]&0xe0 != 0x20 { return false }
	if b[0] == 0x20 && b[1] == 0x01 && (b[2] == 0x00 && (b[3] == 0x00 || b[3] == 0x02 || b[3] == 0x10) || b[2] == 0x0d && b[3] == 0xb8) { return false }
	if b[0] == 0x20 && b[1] == 0x02 { return false }
	return true
}

func validateURL(raw string) (*url.URL, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil { return nil, errors.New("invalid or prohibited URL") }
	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" { return nil, errors.New("non-standard port blocked") }
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") { return nil, errors.New("local hostname blocked") }
	if ip := net.ParseIP(host); ip != nil && !publicIP(ip) { return nil, errors.New("non-public IP blocked") }
	return u, nil
}

func (g *gateway) resolvePublic(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !publicIP(ip) { return nil, errors.New("non-public IP blocked") }
		return ip, nil
	}
	answers, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(answers) == 0 { return nil, errors.New("DNS resolution failed") }
	var chosen net.IP
	for _, answer := range answers {
		if !publicIP(answer.IP) { return nil, errors.New("hostname resolves to a non-public IP") }
		if chosen == nil { chosen = answer.IP }
	}
	return chosen, nil
}

func dialPinned(ctx context.Context, network string, ip net.IP, port string) (net.Conn, error) {
	if ip == nil || port == "" { return nil, errors.New("missing pinned destination") }
	dialer := &net.Dialer{Timeout: 8*time.Second, KeepAlive: -1}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (g *gateway) clientFor(host, port string, ip net.IP) *http.Client {
	if g.clientFactory != nil { return g.clientFactory(host, ip) }
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialPinned(ctx, network, ip, port)
		},
	}
	return &http.Client{Transport: transport, Timeout: 20*time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 { return errors.New("redirect limit exceeded") }
		next, err := validateURL(req.URL.String()); if err != nil { return err }
		if next.Scheme+"://"+next.Host != via[0].URL.Scheme+"://"+via[0].URL.Host { return errors.New("cross-origin redirect blocked") }
		return nil
	}}
}

func (g *gateway) fetchTarget(ctx context.Context, raw string) (*http.Response, []byte, error) {
	u, err := validateURL(raw); if err != nil { return nil, nil, err }
	ip, err := g.resolvePublic(ctx, u.Hostname()); if err != nil { return nil, nil, err }
	port := u.Port(); if port == "" { if u.Scheme == "https" { port = "443" } else { port = "80" } }; client := g.clientFor(u.Hostname(), port, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil); if err != nil { return nil,nil,err }
	req.Header.Set("User-Agent", "QA-Bug-Tracker-Egress/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req); if err != nil { return nil,nil,errors.New("outbound request failed") }
	defer resp.Body.Close()
	if resp.ContentLength > maxResponseBytes { return nil,nil,errors.New("response exceeds size limit") }
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1)); if err != nil { return nil,nil,errors.New("response read failed") }
	if len(body) > maxResponseBytes { return nil,nil,errors.New("response exceeds size limit") }
	return resp, body, nil
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet { w.WriteHeader(http.StatusNoContent); return }
	if r.Method != http.MethodPost || r.URL.Path != "/fetch" { http.Error(w, "not found", http.StatusNotFound); return }
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if g.token == "" || len(supplied) != len(g.token) || subtle.ConstantTimeCompare([]byte(supplied), []byte(g.token)) != 1 { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input fetchRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.URL == "" { http.Error(w, "invalid request", http.StatusBadRequest); return }
	resp, body, err := g.fetchTarget(r.Context(), input.URL)
	if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	headers := map[string]string{}
	for _, key := range []string{"Content-Type", "Content-Language", "Last-Modified"} { if value := resp.Header.Get(key); value != "" { headers[key] = value } }
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(fetchResponse{Status: resp.StatusCode, Header: headers, Body: body})
}

func main() {
	token := os.Getenv("EGRESS_GATEWAY_TOKEN")
	if len(token) < 32 { log.Fatal("EGRESS_GATEWAY_TOKEN must contain at least 32 characters") }
	addr := os.Getenv("PORT"); if addr == "" { addr = "8080" }
	if _, err := strconv.Atoi(addr); err != nil { log.Fatal("invalid PORT") }
	g := &gateway{token: token, resolver: systemResolver{}}
	server := &http.Server{Addr: ":"+addr, Handler: g, ReadHeaderTimeout: 5*time.Second, ReadTimeout: 10*time.Second, WriteTimeout: 25*time.Second, IdleTimeout: 30*time.Second}
	log.Fatal(server.ListenAndServe())
}

