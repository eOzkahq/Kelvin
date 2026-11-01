package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/metrics"
	"go.uber.org/zap"
)

// MetricsRecorder defines the operational metrics contract for egress violations.
type MetricsRecorder interface {
	IncResourceViolation(v metrics.ViolationType)
	IncTermination(c metrics.TerminationCause)
}

// Proxy is a local, sandboxed anti-SSRF egress proxy that intercepts outbound
// HTTP and HTTPS traffic from scanner containers or local processes. It enforces
// strict scope boundaries, DNS pinning, RFC 1918 / metadata deny lists, and
// emits observable security alarms when violations occur.
type Proxy struct {
	policy      *ScannerEgressPolicy
	listener    net.Listener
	server      *http.Server
	logger      *zap.Logger
	metrics     MetricsRecorder
	broadcaster *ViolationBroadcaster
	dialer      *net.Dialer
	transport   *http.Transport
	endpoint    string

	mu     sync.Mutex
	closed bool
}

// NewProxy provisions and starts an ephemeral egress proxy bound to 127.0.0.1.
func NewProxy(policy *ScannerEgressPolicy, logger *zap.Logger, mr MetricsRecorder) (*Proxy, error) {
	if policy == nil {
		return nil, errors.New("egress: cannot start proxy with nil policy")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("egress: failed to bind local proxy listener: %w", err)
	}

	broadcaster := NewViolationBroadcaster()
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	p := &Proxy{
		policy:      policy,
		listener:    listener,
		logger:      logger,
		metrics:     mr,
		broadcaster: broadcaster,
		dialer:      dialer,
		endpoint:    fmt.Sprintf("http://%s", listener.Addr().String()),
	}

	// Transport configured with pinned dialer
	p.transport = &http.Transport{
		Proxy:                 nil, // Never chain to external proxy
		DialContext:           p.dialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}

	p.server = &http.Server{
		Handler:      http.HandlerFunc(p.serveHTTP),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		if err := p.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.Error("egress: proxy server terminated unexpectedly", zap.Error(err))
		}
	}()

	return p, nil
}

// Endpoint returns the HTTP URL of this local proxy (e.g. "http://127.0.0.1:54321").
func (p *Proxy) Endpoint() string {
	return p.endpoint
}

// Addr returns the net.Addr of this proxy listener.
func (p *Proxy) Addr() net.Addr {
	return p.listener.Addr()
}

// AddViolationListener registers an observer for egress security violations.
func (p *Proxy) AddViolationListener(l ViolationListener) {
	p.broadcaster.AddListener(l)
}

// Violations returns a snapshot of all observed egress policy violations.
func (p *Proxy) Violations() []ViolationEvent {
	return p.broadcaster.Events()
}

// ViolationsCount reports how many policy violations were blocked by this proxy.
func (p *Proxy) ViolationsCount() int {
	return p.broadcaster.Count()
}

// Close shuts down the proxy server and listener immediately.
func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	return p.server.Shutdown(ctx)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.RequestURI)
	if err != nil {
		host = r.RequestURI
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 443
	}

	validatedIP, err := p.policy.ValidateDestination(r.Context(), host, port, "https")
	if err != nil {
		p.recordViolation(host, validatedIP.String(), port, "https", err.Error())
		w.Header().Set("X-Kelvin-Egress-Blocked", "true")
		http.Error(w, fmt.Sprintf("egress: destination blocked by policy: %v", err), http.StatusForbidden)
		return
	}

	// Destination is compliant; establish pinned tunnel
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "egress: client hijacking unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("egress: hijack failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	targetAddr := net.JoinHostPort(validatedIP.String(), strconv.Itoa(port))
	targetConn, err := p.dialer.DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Acknowledge CONNECT
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Bidirectional tunnel relay
	relayConnections(clientConn, targetConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil {
		http.Error(w, "egress: nil request URL", http.StatusBadRequest)
		return
	}

	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := r.URL.Hostname()
	portStr := r.URL.Port()
	port := 80
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			port = p
		}
	} else if strings.EqualFold(scheme, "https") {
		port = 443
	}

	validatedIP, err := p.policy.ValidateDestination(r.Context(), host, port, scheme)
	if err != nil {
		p.recordViolation(host, validatedIP.String(), port, scheme, err.Error())
		w.Header().Set("X-Kelvin-Egress-Blocked", "true")
		http.Error(w, fmt.Sprintf("egress: destination blocked by policy: %v", err), http.StatusForbidden)
		return
	}

	// Clone request for pinned forwarding
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // Required by http.Client
	if outReq.Header == nil {
		outReq.Header = make(http.Header)
	}
	removeHopByHopHeaders(outReq.Header)

	// Preserve original host header for virtual hosting, but dial pinned numeric IP
	outReq.Host = r.Host
	if outReq.Host == "" {
		outReq.Host = host
	}
	outReq.URL.Host = net.JoinHostPort(validatedIP.String(), strconv.Itoa(port))
	outReq.URL.Scheme = scheme

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("egress: upstream roundtrip failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.dialer.DialContext(ctx, network, addr)
}

func (p *Proxy) recordViolation(dest, ip string, port int, proto, reason string) {
	p.logger.Warn("SECURITY ALARM: egress policy violation blocked",
		zap.String("scanner", p.policy.Scanner),
		zap.String("target", p.policy.Target),
		zap.String("requested_destination", dest),
		zap.String("resolved_ip", ip),
		zap.Int("port", port),
		zap.String("protocol", proto),
		zap.String("reason", reason),
	)

	if p.metrics != nil {
		p.metrics.IncResourceViolation(metrics.ViolationNetwork)
	}

	p.broadcaster.Record(ViolationEvent{
		Timestamp:            time.Now().UTC(),
		Scanner:              p.policy.Scanner,
		Target:               p.policy.Target,
		RequestedDestination: dest,
		ResolvedIP:           ip,
		Port:                 port,
		Protocol:             proto,
		Reason:               reason,
	})
}

func relayConnections(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Close writing half if possible
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyHalf(c1, c2)
	go copyHalf(c2, c1)

	wg.Wait()
}

func removeHopByHopHeaders(h http.Header) {
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, header := range hopHeaders {
		h.Del(header)
	}
}

var _ = netip.Addr{}

