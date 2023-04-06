/**
 * Created by wuhanjie on 2023/3/29 16:24
 */

package goproxy

import (
	"bufio"
	"net"
	"net/http"
)

type ConnBuffer struct {
	net.Conn
	buf *bufio.ReadWriter
}

func NewConnBuffer(conn net.Conn, buf *bufio.ReadWriter) *ConnBuffer {
	if buf == nil {
		buf = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	}
	
	return &ConnBuffer{Conn: conn, buf: buf}
}

func (cb *ConnBuffer) BufferReader() *bufio.Reader {
	return cb.buf.Reader
}

func (cb *ConnBuffer) Read(b []byte) (n int, err error) {
	return cb.buf.Read(b)
}

func (cb *ConnBuffer) Peek(n int) ([]byte, error) {
	return cb.buf.Peek(n)
}

func (cb *ConnBuffer) Write(p []byte) (n int, err error) {
	n, err = cb.buf.Write(p)
	if err != nil {
		return 0, err
	}
	return n, cb.buf.Flush()
}

func (cb *ConnBuffer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return cb.Conn, cb.buf, nil
}

func (cb *ConnBuffer) WriteHeader(_ int) {}

func (cb *ConnBuffer) Header() http.Header {
	return nil
}
