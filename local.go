package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	bufSize = 64 * 1024
)

type Local struct {
	cfg      *Config
	listener net.Listener
	conns    map[string]*LocalConn
	mu       sync.RWMutex
	closed   bool
}

type LocalConn struct {
	id         string
	conn       net.Conn
	encryptor  *Encryptor
	ssProtocol *ShadowsocksProtocol
	remoteConn net.Conn
	mu         sync.Mutex
}

func NewLocal(cfg *Config) *Local {
	return &Local{
		cfg:   cfg,
		conns: make(map[string]*LocalConn),
	}
}

func (l *Local) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", l.cfg.LocalPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start local proxy on %s: %v", addr, err)
	}

	l.listener = listener
	l.closed = false

	log.Printf("Shadowsocks local proxy started on %s", addr)
	log.Printf("Remote server: %s:%d, Method: %s, Protocol: %s",
		l.cfg.Server, l.cfg.Port, l.cfg.Method, l.cfg.Protocol)
	log.Printf("Supported: SOCKS5 + HTTP CONNECT")

	go l.acceptLoop()

	return nil
}

func (l *Local) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true
	if l.listener != nil {
		l.listener.Close()
	}

	for _, conn := range l.conns {
		conn.Close()
	}
}

func (l *Local) acceptLoop() {
	for {
		clientConn, err := l.listener.Accept()
		if err != nil {
			l.mu.RLock()
			if l.closed {
				l.mu.RUnlock()
				return
			}
			l.mu.RUnlock()
			continue
		}

		go l.handleConnection(clientConn)
	}
}

func (l *Local) handleConnection(conn net.Conn) {
	connID := conn.RemoteAddr().String()
	lc := &LocalConn{
		id:   connID,
		conn: conn,
	}

	l.mu.Lock()
	l.conns[connID] = lc
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.conns, connID)
		l.mu.Unlock()
		lc.Close()
	}()

	peekBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, peekBuf); err != nil {
		return
	}

	var ssHeader []byte
	var initialPayload []byte
	var destHost string
	var destPort int
	var err error

	if peekBuf[0] == 0x05 {
		ssHeader, initialPayload, destHost, destPort, err = l.handleSocks5(conn, peekBuf[0])
	} else {
		ssHeader, initialPayload, destHost, destPort, err = l.handleHTTP(conn, peekBuf[0])
	}

	if err != nil {
		log.Printf("[%s] Handshake failed: %v", connID, err)
		return
	}

	enc, err := NewEncryptor(l.cfg.Password, l.cfg.Method, false)
	if err != nil {
		log.Printf("[%s] Encryptor init failed: %v", connID, err)
		return
	}
	if err := enc.InitForSend(); err != nil {
		log.Printf("[%s] Send init failed: %v", connID, err)
		return
	}
	key := enc.GetKey()
	sendIV := enc.GetSendIV()
	ssProto, err := NewShadowsocksProtocol(key, sendIV, l.cfg.Protocol, l.cfg.ProtocolParam)
	if err != nil {
		log.Printf("[%s] Protocol init failed: %v", connID, err)
		return
	}
	lc.encryptor = enc
	lc.ssProtocol = ssProto

	serverAddr := fmt.Sprintf("%s:%d", l.cfg.Server, l.cfg.Port)
	remoteConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("[%s] Connect server %s failed: %v", connID, serverAddr, err)
		return
	}
	lc.remoteConn = remoteConn

	firstData := ssHeader
	if len(initialPayload) > 0 {
		firstData = append(firstData, initialPayload...)
	}
	firstPacked, err := ssProto.ClientPreEncrypt(firstData)
	if err != nil {
		log.Printf("[%s] Pack first packet failed: %v", connID, err)
		return
	}
	firstEncrypted, err := enc.Encrypt(firstPacked)
	if err != nil {
		log.Printf("[%s] Encrypt first packet failed: %v", connID, err)
		return
	}
	if _, err := remoteConn.Write(firstEncrypted); err != nil {
		log.Printf("[%s] Send first packet failed: %v", connID, err)
		return
	}

	log.Printf("[%s] Tunnel: %s:%d", connID, destHost, destPort)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				packed, perr := ssProto.ClientPreEncrypt(buf[:n])
				if perr != nil {
					return
				}
				encrypted, eerr := enc.Encrypt(packed)
				if eerr != nil {
					return
				}
				if _, werr := remoteConn.Write(encrypted); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer lc.Close()
		buf := make([]byte, bufSize)
		for {
			n, rerr := remoteConn.Read(buf)
			if n > 0 {
				decrypted, derr := enc.Decrypt(buf[:n])
				if derr != nil {
					return
				}
				postDecrypted, perr := ssProto.ClientPostDecrypt(decrypted)
				if perr != nil {
					return
				}
				if len(postDecrypted) > 0 {
					if _, werr := conn.Write(postDecrypted); werr != nil {
						return
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (l *Local) handleSocks5(conn net.Conn, firstByte byte) (ssHeader, initialPayload []byte, host string, port int, err error) {
	buf := make([]byte, 1)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return
	}
	nmethods := int(buf[0])
	if nmethods > 0 {
		methods := make([]byte, nmethods)
		if _, err = io.ReadFull(conn, methods); err != nil {
			return
		}
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		err = fmt.Errorf("bad SOCKS version %d", reqHdr[0])
		return
	}
	cmd := int(reqHdr[1])
	atyp := int(reqHdr[3])
	if cmd != CmdConnect {
		conn.Write(BuildSocks5UnsupportedCmd())
		err = fmt.Errorf("unsupported cmd %d", cmd)
		return
	}

	ssHeader = append(ssHeader, byte(atyp))
	switch atyp {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		ssHeader = append(ssHeader, addr...)
		host = net.IP(addr).String()
	case AddrTypeHost:
		addrLenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, addrLenBuf); err != nil {
			return
		}
		ssHeader = append(ssHeader, addrLenBuf...)
		addr := make([]byte, int(addrLenBuf[0]))
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		ssHeader = append(ssHeader, addr...)
		host = string(addr)
	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		ssHeader = append(ssHeader, addr...)
		host = net.IP(addr).String()
	default:
		err = fmt.Errorf("unsupported atyp %d", atyp)
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	ssHeader = append(ssHeader, portBuf...)
	port = int(portBuf[0])<<8 | int(portBuf[1])

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return
}

func (l *Local) handleHTTP(conn net.Conn, firstByte byte) (ssHeader, initialPayload []byte, host string, port int, err error) {
	reader := bufio.NewReader(conn)

	line, err := readLineBuf(firstByte, reader)
	if err != nil {
		return
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		conn.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
		err = fmt.Errorf("bad request: %s", line)
		return
	}
	method := strings.ToUpper(parts[0])
	rawURL := parts[1]
	isConnect := method == "CONNECT"

	var headers []string
	for {
		var hdr string
		hdr, err = readLineBuf(0, reader)
		if err != nil {
			return
		}
		if hdr == "" {
			break
		}
		headers = append(headers, hdr)
	}

	var sendRequest []byte
	if isConnect {
		var portStr string
		var splitErr error
		host, portStr, splitErr = net.SplitHostPort(rawURL)
		if splitErr != nil {
			host = rawURL
			portStr = "443"
		}
		port, err = strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			conn.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			err = fmt.Errorf("bad port %s", portStr)
			return
		}
		remaining := reader.Buffered()
		if remaining > 0 {
			initialPayload = make([]byte, remaining)
			_, err = io.ReadFull(reader, initialPayload)
			if err != nil {
				return
			}
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		host, port = parseHostFromURL(rawURL)
		if port == 0 {
			port = 80
		}

		path := rawURL
		if strings.HasPrefix(strings.ToLower(path), "http://") {
			u := path[7:]
			if idx := strings.Index(u, "/"); idx >= 0 {
				path = u[idx:]
			} else {
				path = "/"
			}
		}

		var reqBuf bytes.Buffer
		reqBuf.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, parts[2]))
		for _, h := range headers {
			lowerH := strings.ToLower(h)
			if strings.HasPrefix(lowerH, "proxy-connection") || strings.HasPrefix(lowerH, "proxy-authorization") {
				continue
			}
			reqBuf.WriteString(h)
			reqBuf.WriteString("\r\n")
		}
		reqBuf.WriteString("\r\n")
		remaining := reader.Buffered()
		sendRequest = reqBuf.Bytes()
		if remaining > 0 {
			bodyData := make([]byte, remaining)
			_, err = io.ReadFull(reader, bodyData)
			if err != nil {
				return
			}
			sendRequest = append(sendRequest, bodyData...)
		}
		initialPayload = sendRequest
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ssHeader = append(ssHeader, AddrTypeIPv4)
			ssHeader = append(ssHeader, ip4...)
		} else {
			ssHeader = append(ssHeader, AddrTypeIPv6)
			ssHeader = append(ssHeader, ip.To16()...)
		}
	} else {
		ssHeader = append(ssHeader, AddrTypeHost)
		if len(host) > 255 {
			host = host[:255]
		}
		ssHeader = append(ssHeader, byte(len(host)))
		ssHeader = append(ssHeader, []byte(host)...)
	}
	ssHeader = append(ssHeader, byte(port>>8), byte(port&0xff))

	if isConnect {
		log.Printf("[%s] HTTP CONNECT %s:%d", conn.RemoteAddr(), host, port)
	} else {
		log.Printf("[%s] HTTP %s %s:%d", conn.RemoteAddr(), method, host, port)
	}
	return
}

func parseHostFromURL(rawURL string) (string, int) {
	u := rawURL
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		return u, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func readLineBuf(firstByte byte, reader *bufio.Reader) (string, error) {
	var line []byte
	if firstByte != 0 {
		line = append(line, firstByte)
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return string(line), nil
		}
		line = append(line, b)
	}
}

func (lc *LocalConn) Close() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.conn != nil {
		lc.conn.Close()
		lc.conn = nil
	}
	if lc.remoteConn != nil {
		lc.remoteConn.Close()
		lc.remoteConn = nil
	}
}

func (l *Local) GetConnCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.conns)
}
