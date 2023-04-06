/**
 * Created by wuhanjie on 2023/3/28 15:21
 */

package goproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"wireproxy/pkg/cache"
)

const (
	defaultTargetConnectTimeout = 5 * time.Second
	peerPubKeyHeader            = "PeerPubKey"
	peerIPHeader                = "PeerIp"
	peerConnAddr                = "PeerConnAddr"
	virtualNetProxyPort         = 13033
)

var (
	tunnelEstablishedResponseLine           = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	tunnelInvalidAddrResponseLine           = []byte("HTTP/1.1 400 invalid addr\r\n\r\n")
	tunnelErrPeerPubKeyHeaderResponseLine   = []byte("HTTP/1.1 400 invalid peer pub key header\r\n\r\n")
	tunnelErrPeerIpHeaderResponseLine       = []byte("HTTP/1.1 400 invalid peer ip header\r\n\r\n")
	tunnelErrPeerConnAddrHeaderResponseLine = []byte("HTTP/1.1 400 invalid peer conn addr header\r\n\r\n")
	tunnelConnectErrResponseLine            = []byte("HTTP/1.1 502 can not connect target addr\r\n\r\n")
	tunnelInternalErrResponseLine           = []byte("HTTP/1.1 505 can not connect target addr\r\n\r\n")
)

var (
	bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

type options struct {
	portPeerCache cache.PortPeerCache
	vt            *netstack.Net
	isServer      bool
}

type Option func(options *options)

func WithPortPeerCache(c cache.PortPeerCache) Option {
	return func(opt *options) {
		opt.portPeerCache = c
	}
}

func WithVirtualTun(vt *netstack.Net) Option {
	return func(options *options) {
		options.vt = vt
	}
}
func WithIsServer(isServer bool) Option {
	return func(options *options) {
		options.isServer = isServer
	}
}

type Proxy struct {
	cache.PortPeerCache
	virtualNet *netstack.Net
	isServer   bool
}

type ConnectConn struct {
	net.Conn
	lastResponse *bytes.Buffer
}

func (c *ConnectConn) Read(b []byte) (n int, err error) {
	if c.lastResponse.Len() > 0 {
		return c.lastResponse.Read(b)
	}
	return c.Conn.Read(b)
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodConnect:
		p.tunnelProxy(rw, req)
	default:

	}

}

func (p *Proxy) tunnelProxy(rw http.ResponseWriter, req *http.Request) {

	clientConn, err := hijacker(rw)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()

	targetAddr := req.URL.Host
	// 检测目的是否正常
	if !strings.Contains(targetAddr, ":") {
		_, err = clientConn.Write(tunnelInvalidAddrResponseLine)
		return
	}
	log.Printf("Connect targetAddr: %v, isServer: %v\n", targetAddr, p.isServer)
	if p.isServer {
		// 获取源端口
		// srcPort, err := p.virtualNet.GetAvailablePort()
		// if err != nil {
		// 	_, err = clientConn.Write(tunnelInternalErrResponseLine)
		// 	return
		// }
		// 目前基于链接的，暂时不需要分配源端口
		srcPort := 0

		// 获取peer pub key 跟 peer ip
		// peerPubKey := req.Header.Get(peerPubKeyHeader)
		// if len(peerPubKey) == 0 {
		// 	_, err = clientConn.Write(tunnelErrPeerPubKeyHeaderResponseLine)
		// 	return
		// }
		//
		peerConnAddr := req.Header.Get(peerConnAddr)
		addrPort, err := netip.ParseAddrPort(peerConnAddr)
		log.Printf("peerConnAddr: %v\n", addrPort)
		// pIp := net.ParseIP(peerIp)
		if err != nil {
			_, err = clientConn.Write(tunnelErrPeerConnAddrHeaderResponseLine)
			return
		}
		// 解析对应的pub key
		// var noisePublicKey = new(device.NoisePublicKey)
		// err = noisePublicKey.FromHex(peerPubKey)
		// if err != nil || noisePublicKey.IsZero() {
		// 	_, err = clientConn.Write(tunnelErrPeerPubKeyHeaderResponseLine)
		// 	return
		// }
		//
		// p.Set(srcPort, noisePublicKey)
		// p.virtualNet.DialTCPWithBind(tcpip.FullAddress{Port: uint16(srcPort)}, &net.TCPAddr{})

		vConn, err := p.virtualNetConn(addrPort, targetAddr, srcPort)

		if err != nil {
			_, err = clientConn.Write(tunnelConnectErrResponseLine)
			return
		}
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			if vConn != nil {
				_ = vConn.Close()
			}
			return
		}

		p.transfer(clientConn, vConn)
	} else {
		conn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
		if err != nil {
			_, err = clientConn.Write(tunnelInternalErrResponseLine)
			return
		}
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		p.transfer(clientConn, conn)
	}

}

func (p *Proxy) transfer(src net.Conn, dst net.Conn) {
	go func() {
		buf := bufPool.Get().([]byte)
		// 打印日志
		_, _ = io.CopyBuffer(src, dst, buf)
		bufPool.Put(buf)
		_ = src.Close()
		_ = dst.Close()
	}()
	buf := bufPool.Get().([]byte)
	_, _ = io.CopyBuffer(dst, src, buf)
	_ = dst.Close()
	_ = src.Close()
}

func (p *Proxy) virtualNetConn(target netip.AddrPort, addr string, srcPort int) (net.Conn, error) {
	ctx, cancle := context.WithTimeout(context.Background(), defaultTargetConnectTimeout)

	defer cancle()

	conn, err := p.virtualNet.DialContextTCPWithBind(ctx, tcpip.FullAddress{Port: uint16(srcPort)}, &net.TCPAddr{IP: target.Addr().AsSlice(), Port: int(target.Port())})

	if err != nil {
		return nil, err
	}

	conn.Write([]byte(fmt.Sprintf("CONNECT %v HTTP/1.1\r\n", addr)))
	conn.Write([]byte(fmt.Sprintf("Host: %v\r\n\r\n", addr)))

	var responseBuf bytes.Buffer
	buffer := bufio.NewReader(io.TeeReader(conn, &responseBuf))
	response, err := http.ReadResponse(buffer, nil)

	if err != nil {
		return nil, err
	}
	err = response.Body.Close()

	log.Printf("virtualNetConn err: %v\n", err)

	if response.StatusCode == http.StatusOK {
		resp, err := http.ReadResponse(bufio.NewReader(&responseBuf), nil)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		io.Copy(&buf, resp.Body)
		return &ConnectConn{
			Conn:         conn,
			lastResponse: &buf,
		}, nil
	}

	return nil, errors.New("conn remote error")
}

func hijacker(rw http.ResponseWriter) (*ConnBuffer, error) {
	hj, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("http server 不支持Hijacker")
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("Hijacker 错误")
	}
	return NewConnBuffer(conn, buf), nil
}

func New(opt ...Option) *Proxy {
	opts := &options{}
	for _, o := range opt {
		o(opts)
	}

	if opts.vt == nil {
		panic("virtual tun is not nil")
	}

	proxy := &Proxy{}

	if opts.portPeerCache != nil {
		proxy.PortPeerCache = opts.portPeerCache
	}

	proxy.virtualNet = opts.vt
	proxy.isServer = opts.isServer

	// 设置获取具体peer的方法
	device.GetPubKey = func(port int) *device.NoisePublicKey {
		return proxy.Get(port)
	}

	return proxy
}

var _ http.Handler = &Proxy{}
