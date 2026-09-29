package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type Server struct {
	cfg      *Config
	listener net.Listener
	conns    map[string]*ServerConn
	mu       sync.RWMutex
	closed   bool
}

type ServerConn struct {
	id         string
	conn       net.Conn
	stage      Stage
	encryptor  *Encryptor
	ssProtocol *ShadowsocksProtocol
	remoteConn net.Conn
	mu         sync.Mutex
}

func NewServer(cfg *Config) *Server {
	return &Server{
		cfg:   cfg,
		conns: make(map[string]*ServerConn),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server on %s: %v", addr, err)
	}

	s.listener = listener
	s.closed = false

	log.Printf("Shadowsocks server started on %s", addr)
	log.Printf("Method: %s, Protocol: %s", s.cfg.Method, s.cfg.Protocol)

	go s.acceptLoop()

	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	if s.listener != nil {
		s.listener.Close()
	}

	for _, conn := range s.conns {
		conn.Close()
	}
}

func (s *Server) acceptLoop() {
	for {
		clientConn, err := s.listener.Accept()
		if err != nil {
			s.mu.RLock()
			if s.closed {
				s.mu.RUnlock()
				return
			}
			s.mu.RUnlock()
			log.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConnection(clientConn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), len(s.conns))
	sc := &ServerConn{
		id:    connID,
		conn:  conn,
		stage: StageInit,
	}

	s.mu.Lock()
	s.conns[connID] = sc
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, connID)
		s.mu.Unlock()
		sc.Close()
	}()

	if err := sc.initEncryptor(s.cfg); err != nil {
		log.Printf("Failed to init encryptor for %s: %v", connID, err)
		return
	}

	log.Printf("New client connection: %s from %s", connID, conn.RemoteAddr())

	if err := s.handleFirstPacket(sc); err != nil {
		log.Printf("First packet error from %s: %v", connID, err)
		return
	}

	if sc.stage == StageStream && sc.remoteConn != nil {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			s.handleClientRead(sc)
		}()

		go func() {
			defer wg.Done()
			s.handleRemoteRead(sc, sc.remoteConn)
		}()

		wg.Wait()
	}
}

func (sc *ServerConn) initEncryptor(cfg *Config) error {
	encryptor, err := NewEncryptor(cfg.Password, cfg.Method, false)
	if err != nil {
		return err
	}

	sc.encryptor = encryptor
	return nil
}

func (s *Server) handleFirstPacket(sc *ServerConn) error {
	buf := make([]byte, 65536)
	for {
		n, err := sc.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error from %s: %v", sc.id, err)
			}
			return err
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		decrypted, err := sc.encryptor.Decrypt(data)
		if err != nil {
			return err
		}

		if sc.ssProtocol == nil {
			recvIV := sc.encryptor.GetRecvIV()
			key := sc.encryptor.GetKey()

			ssProto, err := NewShadowsocksProtocol(key, recvIV, s.cfg.Protocol, s.cfg.ProtocolParam)
			if err != nil {
				return err
			}
			sc.ssProtocol = ssProto

			if err := sc.encryptor.InitForSend(); err != nil {
				return err
			}
		}

		processed, err := sc.ssProtocol.ServerPostDecrypt(decrypted)
		if err != nil {
			return err
		}
		if processed == nil || len(processed) == 0 {
			continue
		}

		headerData, err := ParseSocket5Header(processed)
		if err != nil {
			return err
		}

		log.Printf("Request from %s: %s:%d", sc.id, headerData.DestAddr, headerData.DestPort)

		remoteAddr := fmt.Sprintf("%s:%d", headerData.DestAddr, headerData.DestPort)
		remoteConn, err := net.Dial("tcp", remoteAddr)
		if err != nil {
			log.Printf("Failed to connect to remote %s: %v", remoteAddr, err)
			return fmt.Errorf("failed to connect to remote: %v", err)
		}

		sc.remoteConn = remoteConn
		sc.stage = StageStream

		if len(processed) > headerData.HeaderLen {
			remaining := processed[headerData.HeaderLen:]
			if len(remaining) > 0 {
				remoteConn.Write(remaining)
			}
		}

		return nil
	}
}

func (s *Server) handleClientRead(sc *ServerConn) {
	buf := make([]byte, 65536)
	for {
		n, err := sc.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Client read error for %s: %v", sc.id, err)
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		decrypted, err := sc.encryptor.Decrypt(data)
		if err != nil {
			log.Printf("Decrypt error for %s: %v", sc.id, err)
			return
		}

		processed, err := sc.ssProtocol.ServerPostDecrypt(decrypted)
		if err != nil {
			log.Printf("ServerPostDecrypt error for %s: %v", sc.id, err)
			return
		}

		if processed != nil && len(processed) > 0 {
			sc.mu.Lock()
			if sc.remoteConn != nil {
				_, err = sc.remoteConn.Write(processed)
			}
			sc.mu.Unlock()

			if err != nil {
				log.Printf("Write to remote error for %s: %v", sc.id, err)
				return
			}
		}
	}
}

func (s *Server) handleRemoteRead(sc *ServerConn, remoteConn net.Conn) {
	defer func() {
		if sc.conn != nil {
			sc.conn.Close()
		}
		if remoteConn != nil {
			remoteConn.Close()
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, err := remoteConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Remote read error for %s: %v", sc.id, err)
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		ssData, err := sc.ssProtocol.ServerPreEncrypt(data)
		if err != nil {
			log.Printf("ServerPreEncrypt error for %s: %v", sc.id, err)
			return
		}

		encryptedData, err := sc.encryptor.Encrypt(ssData)
		if err != nil {
			log.Printf("Encrypt error for %s: %v", sc.id, err)
			return
		}

		if _, err := sc.conn.Write(encryptedData); err != nil {
			log.Printf("Write to client error for %s: %v", sc.id, err)
			return
		}
	}
}

func (sc *ServerConn) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.conn != nil {
		sc.conn.Close()
		sc.conn = nil
	}
	if sc.remoteConn != nil {
		sc.remoteConn.Close()
		sc.remoteConn = nil
	}
}

func (s *Server) GetConnCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.conns)
}
