package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed binaries/*
var embeddedBinaries embed.FS

// Build information (set by ldflags)
var (
	Version    = "dev"
	BuildTime  = "unknown"
	FrpVersion = "unknown"
)

// FRP message types (from pkg/msg/msg.go)
const (
	TypeLogin             = 'o'
	TypeLoginResp         = '1'
	TypeNewProxy          = 'p'
	TypeNewProxyResp      = '2'
	TypeCloseProxy        = 'c'
	TypeNewWorkConn       = 'w'
	TypeReqWorkConn       = 'r'
	TypeStartWorkConn     = 's'
	TypeNewVisitorConn    = 'v'
	TypeNewVisitorConnResp = '3'
	TypePing              = 'h'
	TypePong              = '4'
	TypeUDPPacket         = 'u'
	TypeNatHoleVisitor    = 'i'
	TypeNatHoleClient     = 'n'
	TypeNatHoleResp       = 'm'
	TypeNatHoleClientDetectOK = 'd'
	TypeNatHoleSid        = '5'
)

// Message structures (from pkg/msg/msg.go)
type Login struct {
	Version      string            `json:"version"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
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
	ProxyName         string            `json:"proxy_name"`
	ProxyType         string            `json:"proxy_type"`
	UseEncryption     bool              `json:"use_encryption"`
	UseCompression    bool              `json:"use_compression"`
	BandwidthLimit    string            `json:"bandwidth_limit"`
	BandwidthLimitMode string           `json:"bandwidth_limit_mode"`
	Group             string            `json:"group"`
	GroupKey          string            `json:"group_key"`
	LocalIP           string            `json:"local_ip"`
	LocalPort         int               `json:"local_port"`
	RemotePort        int               `json:"remote_port"`
	CustomDomains     []string          `json:"custom_domains"`
	SubDomain         string            `json:"subdomain"`
	Locations         []string          `json:"locations"`
	HTTPUser          string            `json:"http_user"`
	HTTPPwd           string            `json:"http_pwd"`
	HostHeaderRewrite string            `json:"host_header_rewrite"`
	Headers           map[string]string `json:"headers"`
	RouteByHTTPUser   string            `json:"route_by_http_user"`
	Metas             map[string]string `json:"metas"`
	Sk                string            `json:"sk"`
	Multiplexer       string            `json:"multiplexer"`
}

type NewProxyResp struct {
	ProxyName string `json:"proxy_name"`
	RunId     string `json:"run_id"`
	RemoteAddr string `json:"remote_addr"`
	Error     string `json:"error"`
}

// BatchTester represents the main application
type BatchTester struct {
	serverAddr    string
	serverPort    int
	token         string
	count         int
	mode          string
	localPort     int
	tempDir       string
	results       []TestResult
	mu            sync.Mutex
	wg            sync.WaitGroup
}

type TestResult struct {
	ID       int           `json:"id"`
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// CryptoReadWriter implements FRP's encryption/decryption
type CryptoReadWriter struct {
	r         io.Reader
	w         io.Writer
	encryptor cipher.Stream
	decryptor cipher.Stream
}

func NewCryptoReadWriter(rw io.ReadWriter, key []byte) (*CryptoReadWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV for encryption
	encryptIV := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
		return nil, err
	}

	// Send IV to peer
	if _, err := rw.Write(encryptIV); err != nil {
		return nil, err
	}

	// Read IV from peer
	decryptIV := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rw, decryptIV); err != nil {
		return nil, err
	}

	encryptor := cipher.NewCFBEncrypter(block, encryptIV)
	decryptor := cipher.NewCFBDecrypter(block, decryptIV)

	return &CryptoReadWriter{
		r:         rw,
		w:         rw,
		encryptor: encryptor,
		decryptor: decryptor,
	}, nil
}

func (crw *CryptoReadWriter) Read(p []byte) (n int, err error) {
	n, err = crw.r.Read(p)
	if n > 0 {
		crw.decryptor.XORKeyStream(p[:n], p[:n])
	}
	return
}

func (crw *CryptoReadWriter) Write(p []byte) (n int, err error) {
	encrypted := make([]byte, len(p))
	crw.encryptor.XORKeyStream(encrypted, p)
	return crw.w.Write(encrypted)
}

func main() {
	var (
		serverAddr = flag.String("server", "", "FRP server address (required)")
		serverPort = flag.Int("port", 7000, "FRP server port")
		token      = flag.String("token", "", "FRP authentication token")
		count      = flag.Int("count", 5, "Number of concurrent frpc instances")
		mode       = flag.String("mode", "batch", "Mode: 'batch' for testing, 'proxy' for protocol analysis")
		localPort  = flag.Int("local-port", 7001, "Local port for proxy mode")
		version    = flag.Bool("version", false, "Show version information")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *version {
		fmt.Printf("FRP Batch Tester\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("FRP Version: %s\n", FrpVersion)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	if *serverAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: --server is required\n\n")
		showHelp()
		os.Exit(1)
	}

	bt := &BatchTester{
		serverAddr: *serverAddr,
		serverPort: *serverPort,
		token:      *token,
		count:      *count,
		mode:       *mode,
		localPort:  *localPort,
	}

	if err := bt.run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Printf(`FRP Batch Tester - Multi-instance testing and protocol analysis tool

USAGE:
    %s [OPTIONS]

OPTIONS:
    --server <addr>     FRP server address (required)
    --port <port>       FRP server port (default: 7000)
    --token <token>     FRP authentication token
    --count <num>       Number of concurrent frpc instances (default: 5)
    --mode <mode>       Operation mode:
                         - batch: Run multiple frpc instances (default)
                         - proxy: Protocol analysis mode
    --local-port <port> Local port for proxy mode (default: 7001)
    --version           Show version information
    --help              Show this help

EXAMPLES:
    # Batch test with 10 instances
    %s --server your-server.com --token your-token --count 10

    # Protocol analysis mode
    %s --mode proxy --server your-server.com --token your-token

    # Custom ports
    %s --server 192.168.1.100 --port 7000 --local-port 7001 --mode proxy

BUILD INFO:
    Version: %s
    Build Time: %s
    FRP Version: %s
    Platform: %s/%s
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], Version, BuildTime, FrpVersion, runtime.GOOS, runtime.GOARCH)
}

func (bt *BatchTester) run() error {
	var err error
	bt.tempDir, err = os.MkdirTemp("", "frp-batch-tester-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(bt.tempDir)

	log("Starting FRP Batch Tester")
	log(fmt.Sprintf("Version: %s, Build: %s, FRP: %s", Version, BuildTime, FrpVersion))
	log(fmt.Sprintf("Target: %s:%d, Mode: %s", bt.serverAddr, bt.serverPort, bt.mode))

	switch bt.mode {
	case "batch":
		return bt.runBatchTest()
	case "proxy":
		return bt.runProxyMode()
	default:
		return fmt.Errorf("unknown mode: %s", bt.mode)
	}
}

func (bt *BatchTester) runProxyMode() error {
	log(fmt.Sprintf("Starting proxy mode on 127.0.0.1:%d", bt.localPort))
	log("Configure your frpc to connect to this proxy address")
	log(fmt.Sprintf("Example: frpc -s 127.0.0.1 -P %d -t %s", bt.localPort, bt.token))

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bt.localPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", bt.localPort, err)
	}
	defer listener.Close()

	log(fmt.Sprintf("✅ Proxy listening on %s", listener.Addr()))

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log(fmt.Sprintf("Accept error: %v", err))
			continue
		}

		go bt.handleProxyConnection(clientConn)
	}
}

func (bt *BatchTester) handleProxyConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	log(fmt.Sprintf("📥 frpc connected from %s", clientAddr))

	// Connect to real FRP server
	serverAddr := fmt.Sprintf("%s:%d", bt.serverAddr, bt.serverPort)
	serverConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log(fmt.Sprintf("❌ Failed to connect to frps at %s: %v", serverAddr, err))
		return
	}
	defer serverConn.Close()

	log(fmt.Sprintf("✅ Connected to frps at %s", serverAddr))

	// Set up encryption if token provided
	var clientRW, serverRW io.ReadWriter = clientConn, serverConn
	
	if bt.token != "" {
		log("🔐 Setting up encryption...")
		
		// Set up crypto for client side
		clientCrypto, err := NewCryptoReadWriter(clientConn, []byte(bt.token))
		if err != nil {
			log(fmt.Sprintf("❌ Failed to setup client encryption: %v", err))
			return
		}
		clientRW = clientCrypto
		
		// Set up crypto for server side
		serverCrypto, err := NewCryptoReadWriter(serverConn, []byte(bt.token))
		if err != nil {
			log(fmt.Sprintf("❌ Failed to setup server encryption: %v", err))
			return
		}
		serverRW = serverCrypto
		
		log("✅ Encryption established")
	}

	// Start message parsing and forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to Server (with parsing)
	go func() {
		defer wg.Done()
		bt.parseAndForward(clientRW, serverRW, "frpc -> frps", true)
	}()

	// Server to Client (forward only)
	go func() {
		defer wg.Done()
		bt.parseAndForward(serverRW, clientRW, "frps -> frpc", false)
	}()

	wg.Wait()
	log(fmt.Sprintf("🔌 Connection closed: %s", clientAddr))
}

func (bt *BatchTester) parseAndForward(src io.Reader, dst io.Writer, direction string, shouldParse bool) {
	buffer := make([]byte, 32*1024)
	msgBuffer := bytes.Buffer{}

	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log(fmt.Sprintf("Read error (%s): %v", direction, err))
			}
			return
		}

		// Forward the data
		if _, err := dst.Write(buffer[:n]); err != nil {
			log(fmt.Sprintf("Write error (%s): %v", direction, err))
			return
		}

		// Parse messages if needed
		if shouldParse {
			msgBuffer.Write(buffer[:n])
			bt.parseMessages(&msgBuffer, direction)
		}
	}
}

func (bt *BatchTester) parseMessages(buffer *bytes.Buffer, direction string) {
	for buffer.Len() >= 9 { // At least header size
		// Read message header
		msgType := buffer.Bytes()[0]
		msgLen := binary.BigEndian.Uint64(buffer.Bytes()[1:9])

		// Check if we have complete message
		if buffer.Len() < int(9+msgLen) {
			break // Wait for more data
		}

		// Extract complete message
		header := make([]byte, 9)
		buffer.Read(header)
		
		msgData := make([]byte, msgLen)
		buffer.Read(msgData)

		// Parse specific message types
		if msgType == TypeLogin || msgType == TypeNewProxy {
			bt.parseAndDisplayMessage(msgType, msgData, direction)
		}
	}
}

func (bt *BatchTester) parseAndDisplayMessage(msgType byte, data []byte, direction string) {
	var msgName string
	var msgObj interface{}

	switch msgType {
	case TypeLogin:
		msgName = "Login"
		var login Login
		if err := json.Unmarshal(data, &login); err == nil {
			msgObj = login
		}
	case TypeNewProxy:
		msgName = "NewProxy"
		var newProxy NewProxy
		if err := json.Unmarshal(data, &newProxy); err == nil {
			msgObj = newProxy
		}
	default:
		return
	}

	if msgObj != nil {
		log(fmt.Sprintf("🔍 [DECODE] %s (%s):", direction, msgName))
		if jsonData, err := json.MarshalIndent(msgObj, "", "  "); err == nil {
			fmt.Println(string(jsonData))
		}
		fmt.Println()
	}
}

func (bt *BatchTester) runBatchTest() error {
	// Extract frpc binary
	frpcPath, err := bt.extractFrpcBinary()
	if err != nil {
		return err
	}

	log(fmt.Sprintf("Running batch test with %d instances", bt.count))
	
	bt.results = make([]TestResult, bt.count)
	
	// Run tests concurrently
	for i := 0; i < bt.count; i++ {
		bt.wg.Add(1)
		go bt.runSingleTest(i, frpcPath)
	}
	
	bt.wg.Wait()
	
	// Display results
	bt.displayResults()
	return nil
}

func (bt *BatchTester) runSingleTest(id int, frpcPath string) {
	defer bt.wg.Done()
	
	start := time.Now()
	result := TestResult{ID: id + 1}
	
	// Create config for this instance
	configPath, err := bt.createConfig(id)
	if err != nil {
		result.Error = fmt.Sprintf("Config creation failed: %v", err)
		bt.setResult(id, result)
		return
	}
	defer os.Remove(configPath)
	
	// Run frpc
	cmd := exec.Command(frpcPath, "-c", configPath)
	
	// Capture output
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	
	log(fmt.Sprintf("🚀 [%d] Starting frpc...", id+1))
	
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("Start failed: %v", err)
		result.Duration = time.Since(start)
		bt.setResult(id, result)
		return
	}
	
	// Wait for a short time then kill
	time.Sleep(3 * time.Second)
	
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	
	cmd.Wait()
	
	result.Duration = time.Since(start)
	
	// Check if connection was successful
	outputStr := output.String()
	if strings.Contains(outputStr, "login to server success") || 
	   strings.Contains(outputStr, "start proxy success") {
		result.Success = true
		log(fmt.Sprintf("✅ [%d] Success", id+1))
	} else {
		result.Success = false
		result.Error = "Connection failed"
		log(fmt.Sprintf("❌ [%d] Failed", id+1))
	}
	
	bt.setResult(id, result)
}

func (bt *BatchTester) setResult(id int, result TestResult) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.results[id] = result
}

func (bt *BatchTester) createConfig(id int) (string, error) {
	config := fmt.Sprintf(`[common]
server_addr = %s
server_port = %d
token = %s

[test-proxy-%d]
type = tcp
local_ip = 127.0.0.1
local_port = %d
remote_port = %d
`, bt.serverAddr, bt.serverPort, bt.token, id, 22, 20000+id)

	configPath := filepath.Join(bt.tempDir, fmt.Sprintf("frpc-%d.ini", id))
	return configPath, os.WriteFile(configPath, []byte(config), 0644)
}

func (bt *BatchTester) extractFrpcBinary() (string, error) {
	// Try to find local frpc first
	localFrpc := "frpc"
	if runtime.GOOS == "windows" {
		localFrpc = "frpc.exe"
	}
	
	if _, err := os.Stat(localFrpc); err == nil {
		log(fmt.Sprintf("Using local frpc binary: %s", localFrpc))
		return filepath.Abs(localFrpc)
	}

	// Determine the binary name based on current platform
	var binaryName string
	switch runtime.GOOS {
	case "windows":
		binaryName = fmt.Sprintf("frpc_%s_%s.exe", runtime.GOOS, runtime.GOARCH)
	default:
		binaryName = fmt.Sprintf("frpc_%s_%s", runtime.GOOS, runtime.GOARCH)
	}

	log(fmt.Sprintf("Looking for embedded binary: binaries/%s", binaryName))

	// Try to read the binary from embedded files
	data, err := embeddedBinaries.ReadFile("binaries/" + binaryName)
	if err != nil {
		return "", fmt.Errorf(`frpc binary not found for %s/%s.

To use this tool:
1. Download the appropriate frpc binary from https://github.com/fatedier/frp/releases
2. Place it in the same directory as this program and name it 'frpc' (or 'frpc.exe' on Windows)
3. Or use --mode proxy for protocol analysis without running frpc`, 
			runtime.GOOS, runtime.GOARCH)
	}

	// Check if the binary data looks valid
	if len(data) < 1000 {
		return "", fmt.Errorf("embedded frpc binary seems corrupted (too small: %d bytes)", len(data))
	}

	// Write to temp file
	frpcPath := filepath.Join(bt.tempDir, "frpc")
	if runtime.GOOS == "windows" {
		frpcPath += ".exe"
	}

	if err := os.WriteFile(frpcPath, data, 0755); err != nil {
		return "", fmt.Errorf("failed to write frpc binary: %v", err)
	}

	log(fmt.Sprintf("Extracted frpc binary to: %s (size: %d bytes)", frpcPath, len(data)))
	return frpcPath, nil
}

func (bt *BatchTester) displayResults() {
	fmt.Println()
	log("=== Test Results ===")
	
	var successful, failed int
	var totalDuration time.Duration
	
	for _, result := range bt.results {
		status := "❌ FAILED"
		if result.Success {
			status = "✅ SUCCESS"
			successful++
		} else {
			failed++
		}
		
		errorMsg := ""
		if result.Error != "" {
			errorMsg = fmt.Sprintf(" (%s)", result.Error)
		}
		
		fmt.Printf("[%2d] %s - %v%s\n", result.ID, status, result.Duration.Round(time.Millisecond), errorMsg)
		totalDuration += result.Duration
	}
	
	fmt.Println()
	log(fmt.Sprintf("Summary: %d successful, %d failed, %.2fs average", 
		successful, failed, totalDuration.Seconds()/float64(len(bt.results))))
	
	successRate := float64(successful) / float64(len(bt.results)) * 100
	log(fmt.Sprintf("Success rate: %.1f%%", successRate))
}

func log(msg string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}
