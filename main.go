package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// Message types from frp
const (
	TypeLogin         = 'o'
	TypeLoginResp     = '1'
	TypeNewProxy      = 'p'
	TypeNewProxyResp  = '2'
	TypeCloseProxy    = 'c'
	TypeNewWorkConn   = 'w'
	TypeReqWorkConn   = 'r'
	TypeStartWorkConn = 's'
	TypeNewVisitorConn = 'v'
	TypeNewVisitorConnResp = '3'
	TypePing          = 'h'
	TypePong          = '4'
	TypeUDPPacket     = 'u'
	TypeNatHoleVisitor = 'i'
	TypeNatHoleClient  = 'n'
	TypeNatHoleResp    = 'm'
	TypeNatHoleClientDetectOK = 'd'
	TypeNatHoleSid     = '5'
)

// Message structures from frp
type Login struct {
	Version      string            `json:"version"`
	Hostname     string            `json:"hostname"`
	Os           string            `json:"os"`
	Arch         string            `json:"arch"`
	User         string            `json:"user"`
	PrivilegeKey string            `json:"privilege_key"`
	Timestamp    int64             `json:"timestamp"`
	RunId        string            `json:"run_id"`
	Metas        map[string]string `json:"metas"`
	PoolCount    int               `json:"pool_count"`
}

type LoginResp struct {
	Version       string `json:"version"`
	RunId         string `json:"run_id"`
	ServerUDPPort int    `json:"server_udp_port"`
	Error         string `json:"error"`
}

type NewProxy struct {
	ProxyName      string            `json:"proxy_name"`
	ProxyType      string            `json:"proxy_type"`
	UseEncryption  bool              `json:"use_encryption"`
	UseCompression bool              `json:"use_compression"`
	Group          string            `json:"group"`
	GroupKey       string            `json:"group_key"`
	Metas          map[string]string `json:"metas"`
	
	// HTTP
	CustomDomains     []string          `json:"custom_domains"`
	SubDomain         string            `json:"subdomain"`
	Locations         []string          `json:"locations"`
	HTTPUser          string            `json:"http_user"`
	HTTPPwd           string            `json:"http_pwd"`
	HostHeaderRewrite string            `json:"host_header_rewrite"`
	Headers           map[string]string `json:"headers"`
	
	// TCP
	RemotePort int `json:"remote_port"`
	
	// UDP
	// RemotePort is used
	
	// STCP & XTCP
	Sk string `json:"sk"`
	
	// TCP MUX
	Multiplexer string `json:"multiplexer"`
}

type NewProxyResp struct {
	ProxyName string `json:"proxy_name"`
	RunId     string `json:"run_id"`
	Error     string `json:"error"`
	
	// TCP
	RemoteAddr string `json:"remote_addr"`
}

type CloseProxy struct {
	ProxyName string `json:"proxy_name"`
}

type NewWorkConn struct {
	RunId        string `json:"run_id"`
	PrivilegeKey string `json:"privilege_key"`
	Timestamp    int64  `json:"timestamp"`
}

type ReqWorkConn struct {
}

type StartWorkConn struct {
	ProxyName string `json:"proxy_name"`
}

type NewVisitorConn struct {
	ProxyName      string `json:"proxy_name"`
	SignKey        string `json:"sign_key"`
	Timestamp      int64  `json:"timestamp"`
	UseEncryption  bool   `json:"use_encryption"`
	UseCompression bool   `json:"use_compression"`
}

type NewVisitorConnResp struct {
	ProxyName string `json:"proxy_name"`
	Error     string `json:"error"`
}

type Ping struct {
	PrivilegeKey string `json:"privilege_key"`
	Timestamp    int64  `json:"timestamp"`
}

type Pong struct {
	Error string `json:"error"`
}

// Config holds the proxy configuration
type Config struct {
	LocalAddr  string
	RemoteAddr string
	Token      string
}

// CryptoReadWriter provides encryption/decryption for network connections
type CryptoReadWriter struct {
	conn     io.ReadWriteCloser
	encrypt  cipher.Stream
	decrypt  cipher.Stream
	iv       []byte
}

// NewCryptoReadWriter creates a new encrypted read/writer
func NewCryptoReadWriter(conn io.ReadWriteCloser, key []byte) (*CryptoReadWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Send IV to peer
	if _, err := conn.Write(iv); err != nil {
		return nil, err
	}

	// Read IV from peer
	peerIV := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, peerIV); err != nil {
		return nil, err
	}

	encrypt := cipher.NewCFBEncrypter(block, iv)
	decrypt := cipher.NewCFBDecrypter(block, peerIV)

	return &CryptoReadWriter{
		conn:    conn,
		encrypt: encrypt,
		decrypt: decrypt,
		iv:      iv,
	}, nil
}

func (c *CryptoReadWriter) Read(p []byte) (n int, err error) {
	n, err = c.conn.Read(p)
	if n > 0 {
		c.decrypt.XORKeyStream(p[:n], p[:n])
	}
	return
}

func (c *CryptoReadWriter) Write(p []byte) (n int, err error) {
	encrypted := make([]byte, len(p))
	c.encrypt.XORKeyStream(encrypted, p)
	return c.conn.Write(encrypted)
}

func (c *CryptoReadWriter) Close() error {
	return c.conn.Close()
}

// MessageReader reads and parses frp protocol messages
type MessageReader struct {
	conn io.Reader
}

// NewMessageReader creates a new message reader
func NewMessageReader(conn io.Reader) *MessageReader {
	return &MessageReader{conn: conn}
}

// ReadMessage reads a single frp message
func (r *MessageReader) ReadMessage() (byte, []byte, error) {
	// Read message type (1 byte)
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r.conn, typeBuf); err != nil {
		return 0, nil, err
	}
	
	// Read message length (8 bytes, big endian)
	lenBuf := make([]byte, 8)
	if _, err := io.ReadFull(r.conn, lenBuf); err != nil {
		return 0, nil, err
	}
	
	length := binary.BigEndian.Uint64(lenBuf)
	if length > 10*1024*1024 { // 10MB limit
		return 0, nil, fmt.Errorf("message too large: %d bytes", length)
	}
	
	// Read message content
	content := make([]byte, length)
	if _, err := io.ReadFull(r.conn, content); err != nil {
		return 0, nil, err
	}
	
	return typeBuf[0], content, nil
}

// MessageWriter writes frp protocol messages
type MessageWriter struct {
	conn io.Writer
}

// NewMessageWriter creates a new message writer
func NewMessageWriter(conn io.Writer) *MessageWriter {
	return &MessageWriter{conn: conn}
}

// WriteMessage writes a frp message
func (w *MessageWriter) WriteMessage(msgType byte, content []byte) error {
	// Write message type
	if _, err := w.conn.Write([]byte{msgType}); err != nil {
		return err
	}
	
	// Write message length
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(content)))
	if _, err := w.conn.Write(lenBuf); err != nil {
		return err
	}
	
	// Write message content
	_, err := w.conn.Write(content)
	return err
}

// ProxyConnection handles a single proxy connection
type ProxyConnection struct {
	clientConn net.Conn
	serverConn net.Conn
	config     *Config
}

// NewProxyConnection creates a new proxy connection
func NewProxyConnection(clientConn net.Conn, config *Config) (*ProxyConnection, error) {
	serverConn, err := net.Dial("tcp", config.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %v", err)
	}
	
	log(fmt.Sprintf("Connected to frps at %s", config.RemoteAddr))
	
	return &ProxyConnection{
		clientConn: clientConn,
		serverConn: serverConn,
		config:     config,
	}, nil
}

// Handle processes the proxy connection
func (p *ProxyConnection) Handle() {
	defer p.clientConn.Close()
	defer p.serverConn.Close()
	
	var clientReader io.Reader = p.clientConn
	var serverWriter io.Writer = p.serverConn
	var serverReader io.Reader = p.serverConn
	var clientWriter io.Writer = p.clientConn
	
	// Setup encryption if token is provided
	if p.config.Token != "" {
		key := make([]byte, 32)
		copy(key, []byte(p.config.Token))
		
		// Setup client-side encryption
		clientCrypto, err := NewCryptoReadWriter(
			struct {
				io.Reader
				io.Writer
				io.Closer
			}{clientReader, clientWriter, p.clientConn},
			key,
		)
		if err != nil {
			log(fmt.Sprintf("Failed to setup client encryption: %v", err))
			return
		}
		clientReader = clientCrypto
		clientWriter = clientCrypto
		
		// Setup server-side encryption
		serverCrypto, err := NewCryptoReadWriter(
			struct {
				io.Reader
				io.Writer
				io.Closer
			}{serverReader, serverWriter, p.serverConn},
			key,
		)
		if err != nil {
			log(fmt.Sprintf("Failed to setup server encryption: %v", err))
			return
		}
		serverReader = serverCrypto
		serverWriter = serverCrypto
	}
	
	// Start goroutines for bidirectional forwarding
	done := make(chan struct{}, 2)
	
	// Client to server with message parsing
	go func() {
		defer func() { done <- struct{}{} }()
		p.forwardWithParsing(clientReader, serverWriter, "frpc -> frps")
	}()
	
	// Server to client (simple forwarding)
	go func() {
		defer func() { done <- struct{}{} }()
		p.forwardSimple(serverReader, clientWriter, "frps -> frpc")
	}()
	
	// Wait for either direction to finish
	<-done
}

// forwardWithParsing forwards data while parsing frp messages
func (p *ProxyConnection) forwardWithParsing(src io.Reader, dst io.Writer, direction string) {
	reader := NewMessageReader(src)
	writer := NewMessageWriter(dst)
	
	for {
		msgType, content, err := reader.ReadMessage()
		if err != nil {
			if err != io.EOF {
				log(fmt.Sprintf("Error reading message (%s): %v", direction, err))
			}
			return
		}
		
		// Parse and log specific message types
		p.parseAndLogMessage(msgType, content, direction)
		
		// Forward the message
		if err := writer.WriteMessage(msgType, content); err != nil {
			log(fmt.Sprintf("Error forwarding message (%s): %v", direction, err))
			return
		}
	}
}

// forwardSimple performs simple data forwarding
func (p *ProxyConnection) forwardSimple(src io.Reader, dst io.Writer, direction string) {
	_, err := io.Copy(dst, src)
	if err != nil && err != io.EOF {
		log(fmt.Sprintf("Error forwarding data (%s): %v", direction, err))
	}
}

// parseAndLogMessage parses and logs specific message types
func (p *ProxyConnection) parseAndLogMessage(msgType byte, content []byte, direction string) {
	switch msgType {
	case TypeLogin:
		var msg Login
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (Login):\n%s", direction, 
				p.sanitizeOutput(string(prettyJSON))))
		}
		
	case TypeNewProxy:
		var msg NewProxy
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (NewProxy):\n%s", direction, 
				p.sanitizeOutput(string(prettyJSON))))
		}
		
	case TypeLoginResp:
		var msg LoginResp
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (LoginResp):\n%s", direction, 
				p.sanitizeOutput(string(prettyJSON))))
		}
	}
}

// sanitizeOutput removes potentially sensitive information from output
func (p *ProxyConnection) sanitizeOutput(input string) string {
	// Remove or mask sensitive fields
	re := regexp.MustCompile(`("privilege_key"|"sign_key"|"group_key"|"http_pwd")\s*:\s*"[^"]*"`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		parts := strings.Split(match, ":")
		if len(parts) >= 2 {
			return parts[0] + `: "***MASKED***"`
		}
		return match
	})
}

// ProxyServer represents the main proxy server
type ProxyServer struct {
	config *Config
}

// NewProxyServer creates a new proxy server
func NewProxyServer(config *Config) *ProxyServer {
	return &ProxyServer{config: config}
}

// Start starts the proxy server
func (s *ProxyServer) Start() error {
	listener, err := net.Listen("tcp", s.config.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.config.LocalAddr, err)
	}
	defer listener.Close()
	
	log(fmt.Sprintf("Proxy listening on %s", s.config.LocalAddr))
	log(fmt.Sprintf("Forwarding to frps at %s", s.config.RemoteAddr))
	if s.config.Token != "" {
		log("Encryption enabled")
	} else {
		log("WARNING: No token provided, running in non-encrypted mode")
	}
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log(fmt.Sprintf("Failed to accept connection: %v", err))
			continue
		}
		
		log(fmt.Sprintf("frpc connected from %s", conn.RemoteAddr()))
		
		go func(clientConn net.Conn) {
			proxyConn, err := NewProxyConnection(clientConn, s.config)
			if err != nil {
				log(fmt.Sprintf("Failed to create proxy connection: %v", err))
				clientConn.Close()
				return
			}
			
			proxyConn.Handle()
			log(fmt.Sprintf("Connection from %s closed", clientConn.RemoteAddr()))
		}(conn)
	}
}

// log prints a timestamped log message
func log(message string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
}

func main() {
	config := &Config{}
	
	flag.StringVar(&config.LocalAddr, "local-addr", "127.0.0.1:7001", 
		"Local address to listen on")
	flag.StringVar(&config.RemoteAddr, "remote-addr", "", 
		"Remote frps server address (required)")
	flag.StringVar(&config.Token, "token", "", 
		"frp authentication token (for encryption)")
	
	flag.Parse()
	
	if config.RemoteAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: --remote-addr is required\n")
		flag.Usage()
		os.Exit(1)
	}
	
	log("Starting FRP Batch Tester")
	log(fmt.Sprintf("Version: 1.0.0"))
	
	server := NewProxyServer(config)
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
