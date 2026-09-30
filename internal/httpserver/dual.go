// Serving HTTPS and plain HTTP on one TCP port.
//
// Every TLS connection opens with a handshake record whose first byte is
// 0x16 (content type "handshake"); an HTTP/1.x request line never starts
// with that byte. Dual peeks that one byte per connection and hands the
// connection either to crypto/tls or straight through. That lets the
// standalone server add https://oidc.dev.test without breaking existing
// plain-HTTP consumers on the same port (the ai-gateway deploy pattern).
//
// The peek happens lazily on the connection's first Read, never in Accept:
// a client that connects and sends nothing must not stall the accept loop.
// http.Server's ReadHeaderTimeout deadline is set on the connection before
// that first Read, so it bounds the peek and the TLS handshake as well.
package httpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// tlsHandshakeByte is the TLS record content type for handshake messages.
const tlsHandshakeByte = 0x16

// Dual wraps ln so each accepted connection speaks TLS (using cfg) when its
// first byte is a TLS handshake record, and plaintext otherwise.
func Dual(ln net.Listener, cfg *tls.Config) net.Listener {
	return &dualListener{Listener: ln, cfg: cfg}
}

// NewServer builds the http.Server for a Dual-served handler: the
// ReadHeaderTimeout bounds the sniff peek and the TLS handshake, and
// ConnContext records the sniff decision so RequestIsTLS can report https
// for TLS traffic net/http never labeled (it never sees the *tls.Conn).
func NewServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       dualConnContext,
	}
}

type connCtxKey struct{}

func dualConnContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*sniffConn); ok {
		return context.WithValue(ctx, connCtxKey{}, c)
	}
	return ctx
}

// RequestIsTLS reports whether the connection serving this request speaks
// TLS: either net/http saw a real *tls.Conn (r.TLS, the non-dual case) or
// the Dual sniff resolved this connection to its TLS branch.
func RequestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	c, ok := r.Context().Value(connCtxKey{}).(*sniffConn)
	if !ok {
		return false
	}
	c.resolve()
	_, isTLS := c.inner.(*tls.Conn)
	return isTLS
}

type dualListener struct {
	net.Listener
	cfg *tls.Config
}

func (l *dualListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c, cfg: l.cfg}, nil
}

// sniffConn defers the protocol decision to the first Read or Write.
// Deadlines and addresses come from the embedded raw connection — tls.Conn
// delegates those to the same socket, so both paths share them.
type sniffConn struct {
	net.Conn // raw socket
	cfg      *tls.Config
	once     sync.Once
	inner    net.Conn // *tls.Conn or *peekedConn, set by once
}

func (c *sniffConn) resolve() net.Conn {
	c.once.Do(func() {
		br := bufio.NewReaderSize(c.Conn, 1024)
		pc := &peekedConn{Conn: c.Conn, r: br}
		// A peek error (EOF, deadline) falls through to plaintext: the next
		// Read returns the same error from the buffered reader.
		if b, err := br.Peek(1); err == nil && b[0] == tlsHandshakeByte {
			c.inner = tls.Server(pc, c.cfg)
			return
		}
		c.inner = pc
	})
	return c.inner
}

func (c *sniffConn) Read(p []byte) (int, error)  { return c.resolve().Read(p) }
func (c *sniffConn) Write(p []byte) (int, error) { return c.resolve().Write(p) }

// Close closes the raw socket directly. It must not go through resolve():
// a Close racing a Read that is blocked inside the peek would wait on the
// once forever. Skipping TLS close_notify is harmless for HTTP/1.1, where
// message framing never relies on it.
func (c *sniffConn) Close() error { return c.Conn.Close() }

// peekedConn replays the bytes already buffered by the sniff before
// reading further from the socket.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }
