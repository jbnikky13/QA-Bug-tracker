package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeResolver struct { answers []net.IPAddr; err error }
func (f fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return f.answers, f.err }

func TestPublicIPRejectsSpecialRanges(t *testing.T) {
	for _, raw := range []string{"127.0.0.1","10.0.0.1","169.254.169.254","192.168.1.1","100.64.0.1","192.0.2.1","198.51.100.1","203.0.113.1","224.0.0.1","::1","fc00::1","fe80::1","2001:db8::1","2002::1"} {
		if publicIP(net.ParseIP(raw)) { t.Errorf("expected %s to be rejected", raw) }
	}
	for _, raw := range []string{"8.8.8.8","1.1.1.1","2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(raw)) { t.Errorf("expected %s to be public", raw) }
	}
}

func TestResolvePublicRejectsMixedPublicAndPrivateDNSAnswers(t *testing.T) {
	g := &gateway{resolver: fakeResolver{answers: []net.IPAddr{{IP:net.ParseIP("8.8.8.8")},{IP:net.ParseIP("127.0.0.1")}}}}
	if _, err := g.resolvePublic(context.Background(), "target.example"); err == nil { t.Fatal("mixed DNS answer set must be rejected") }
}

func TestResolvePublicReturnsValidatedAddress(t *testing.T) {
	expected := net.ParseIP("1.1.1.1")
	g := &gateway{resolver: fakeResolver{answers: []net.IPAddr{{IP:expected}}}}
	got, err := g.resolvePublic(context.Background(), "target.example")
	if err != nil { t.Fatal(err) }
	if !got.Equal(expected) { t.Fatalf("got %v, want %v", got, expected) }
}

func TestValidateURLRejectsCredentialsAndUnsafeDestinations(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd","http://user:pass@example.com","http://127.0.0.1","http://169.254.169.254","http://example.com:8080","http://service.internal"} {
		if _, err := validateURL(raw); err == nil { t.Errorf("expected %q to be rejected", raw) }
	}
	if _, err := validateURL("https://example.com/path"); err != nil { t.Fatal(err) }
}

func TestPinnedDialConnectsToSuppliedIPNotHostname(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, e := listener.Accept(); if e == nil { accepted <- conn } }()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil { t.Fatal(err) }
	ip := net.ParseIP("127.0.0.1")
	conn, err := dialPinned(context.Background(), "tcp", ip, port)
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	select {
	case peer := <-accepted: defer peer.Close()
	case <-time.After(time.Second): t.Fatal("pinned IP connection was not accepted")
	}
}

func TestGatewayRequiresBearerToken(t *testing.T) {
	g := &gateway{token:"a-very-long-test-secret-value-123456"}
	req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	res := httptest.NewRecorder()
	g.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized { t.Fatalf("got %d, want 401", res.Code) }
}

func TestGatewayDoesNotExposeUnauthenticatedProxy(t *testing.T) {
	g := &gateway{token:"a-very-long-test-secret-value-123456", resolver:fakeResolver{err:errors.New("must not resolve")}}
	req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	res := httptest.NewRecorder()
	g.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized { t.Fatalf("got %d, want 401", res.Code) }
}
