package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed binaries/*
var embeddedBinaries embed.FS

// Build info will be set during GitHub Actions build
var (
	Version   = "dev"
	BuildTime = "unknown"
	FrpVersion = "unknown"
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

// TestConfig holds test configuration
type TestConfig struct {
	ServerAddr     string
	ServerPort     int
	Token          string
	ProxyName      string
	ProxyType      string
	LocalPort      int
	RemotePort     int
	CustomDomain   string
	SubDomain      string
	HTTPUser       string
	HTTPPwd        string
	TestDuration   time.Duration
	ProxyTimeout   time.Duration
	EnableAnalysis bool
	OutputFormat   string
}

// BatchTester manages multiple frpc instances for testing
type BatchTester struct {
	config      *TestConfig
	tempDir     string
	frpcPath    string
	runningProcs []*os.Process
	mu          sync.Mutex
}

// NewBatchTester creates a new batch tester
func NewBatchTester(config *TestConfig) (*BatchTester, error) {
	tempDir, err := os.MkdirTemp("", "frp-tester-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	tester := &BatchTester{
		config:  config,
		tempDir: tempDir,
	}

	// Extract frpc binary
	frpcPath, err := tester.extractFrpcBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to extract frpc: %v", err)
	}
	tester.frpcPath = frpcPath

	return tester, nil
}

// extractFrpcBinary extracts the appropriate frpc binary for the current platform
func (bt *BatchTester) extractFrpcBinary() (string, error) {
	// Determine the binary name based on current platform
	var binaryName string
	switch runtime.GOOS {
	case "windows":
		binaryName = fmt.Sprintf("frpc_%s_%s.exe", runtime.GOOS, runtime.GOARCH)
	default:
		binaryName = fmt.Sprintf("frpc_%s_%s", runtime.GOOS, runtime.GOARCH)
	}

	log(fmt.Sprintf("Looking for embedded binary: binaries/%s", binaryName))

	// Read the binary from embedded files
	data, err := embeddedBinaries.ReadFile("binaries/" + binaryName)
	if err != nil {
		return "", fmt.Errorf("frpc binary not found for %s/%s: %v", runtime.GOOS, runtime.GOARCH, err)
	}

	// Write to temp file
	frpcPath := filepath.Join(bt.tempDir, "frpc")
	if runtime.GOOS == "windows" {
		frpcPath += ".exe"
	}

	if err := os.WriteFile(frpcPath, data, 0755); err != nil {
		return "", fmt.Errorf("failed to write frpc binary: %v", err)
	}

	log(fmt.Sprintf("Extracted frpc binary to: %s", frpcPath))
	return frpcPath, nil
}

// generateFrpcConfig generates a frpc configuration file
func (bt *BatchTester) generateFrpcConfig(testID int) (string, error) {
	configContent := fmt.Sprintf(`[common]
server_addr = %s
server_port = %d
token = %s

[test_proxy_%d]
type = %s
local_port = %d
`, bt.config.ServerAddr, bt.config.ServerPort, bt.config.Token, testID, bt.config.ProxyType, bt.config.LocalPort+testID)

	if bt.config.ProxyType == "tcp" && bt.config.RemotePort > 0 {
		configContent += fmt.Sprintf("remote_port = %d\n", bt.config.RemotePort+testID)
	}

	if bt.config.ProxyType == "http" {
		if bt.config.CustomDomain != "" {
			configContent += fmt.Sprintf("custom_domains = %s\n", bt.config.CustomDomain)
		}
		if bt.config.SubDomain != "" {
			configContent += fmt.Sprintf("subdomain = %s%d\n", bt.config.SubDomain, testID)
		}
		if bt.config.HTTPUser != "" {
			configContent += fmt.Sprintf("http_user = %s\n", bt.config.HTTPUser)
		}
		if bt.config.HTTPPwd != "" {
			configContent += fmt.Sprintf("http_pwd = %s\n", bt.config.HTTPPwd)
		}
	}

	configPath := filepath.Join(bt.tempDir, fmt.Sprintf("frpc_%d.ini", testID))
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write config file: %v", err)
	}

	return configPath, nil
}

// startFrpcInstance starts a single frpc instance
func (bt *BatchTester) startFrpcInstance(testID int) (*exec.Cmd, error) {
	configPath, err := bt.generateFrpcConfig(testID)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(bt.frpcPath, "-c", configPath)
	cmd.Dir = bt.tempDir

	// Create pipes for stdout/stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start frpc: %v", err)
	}

	bt.mu.Lock()
	bt.runningProcs = append(bt.runningProcs, cmd.Process)
	bt.mu.Unlock()

	// Log output in goroutines
	go bt.logOutput(fmt.Sprintf("frpc[%d] stdout", testID), stdout)
	go bt.logOutput(fmt.Sprintf("frpc[%d] stderr", testID), stderr)

	return cmd, nil
}

// logOutput logs output from frpc processes
func (bt *BatchTester) logOutput(prefix string, reader io.Reader) {
	scanner := make([]byte, 1024)
	for {
		n, err := reader.Read(scanner)
		if err != nil {
			if err != io.EOF {
				log(fmt.Sprintf("[%s] Read error: %v", prefix, err))
			}
			break
		}
		if n > 0 {
			output := strings.TrimSpace(string(scanner[:n]))
			if output != "" {
				log(fmt.Sprintf("[%s] %s", prefix, output))
			}
		}
	}
}

// RunBatchTest runs multiple frpc instances for testing
func (bt *BatchTester) RunBatchTest(count int) error {
	log(fmt.Sprintf("Starting batch test with %d frpc instances", count))

	var wg sync.WaitGroup
	results := make(chan error, count)

	// Start frpc instances
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(testID int) {
			defer wg.Done()
			
			cmd, err := bt.startFrpcInstance(testID)
			if err != nil {
				results <- fmt.Errorf("instance %d failed to start: %v", testID, err)
				return
			}

			// Wait for the specified duration or until process exits
			done := make(chan error, 1)
			go func() {
				done <- cmd.Wait()
			}()

			select {
			case err := <-done:
				if err != nil {
					results <- fmt.Errorf("instance %d exited with error: %v", testID, err)
				} else {
					results <- nil
				}
			case <-time.After(bt.config.TestDuration):
				log(fmt.Sprintf("Test duration reached, stopping instance %d", testID))
				if err := cmd.Process.Kill(); err != nil {
					log(fmt.Sprintf("Failed to kill instance %d: %v", testID, err))
				}
				results <- nil
			}
		}(i)
	}

	// Wait for all instances
	wg.Wait()
	close(results)

	// Collect results
	var errors []error
	for err := range results {
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		log(fmt.Sprintf("Test completed with %d errors:", len(errors)))
		for _, err := range errors {
			log(fmt.Sprintf("  - %v", err))
		}
	} else {
		log("All test instances completed successfully")
	}

	return nil
}

// Cleanup removes temporary files and kills running processes
func (bt *BatchTester) Cleanup() {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Kill all running processes
	for _, proc := range bt.runningProcs {
		if proc != nil {
			proc.Kill()
		}
	}

	// Remove temp directory
	if bt.tempDir != "" {
		os.RemoveAll(bt.tempDir)
	}
}

// ProxyAnalyzer provides analysis functionality (keeping original proxy code)
type ProxyAnalyzer struct {
	config *TestConfig
}

// ... (include all the original crypto and message parsing code here) ...

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

// RunProxyAnalysis runs the proxy analysis mode (original functionality)
func (bt *BatchTester) RunProxyAnalysis() error {
	log("Starting proxy analysis mode...")
	
	// Use config values for proxy analysis
	proxyConfig := &struct {
		LocalAddr  string
		RemoteAddr string
		Token      string
	}{
		LocalAddr:  "127.0.0.1:7001",
		RemoteAddr: fmt.Sprintf("%s:%d", bt.config.ServerAddr, bt.config.ServerPort),
		Token:      bt.config.Token,
	}
	
	listener, err := net.Listen("tcp", proxyConfig.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", proxyConfig.LocalAddr, err)
	}
	defer listener.Close()
	
	log(fmt.Sprintf("Proxy analyzer listening on %s", proxyConfig.LocalAddr))
	log(fmt.Sprintf("Forwarding to frps at %s", proxyConfig.RemoteAddr))
	if proxyConfig.Token != "" {
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
			defer clientConn.Close()
			
			serverConn, err := net.Dial("tcp", proxyConfig.RemoteAddr)
			if err != nil {
				log(fmt.Sprintf("Failed to connect to server: %v", err))
				return
			}
			defer serverConn.Close()
			
			log(fmt.Sprintf("Connected to frps at %s", proxyConfig.RemoteAddr))
			
			// Handle the connection (simplified version of original proxy code)
			bt.handleProxyConnection(clientConn, serverConn, proxyConfig.Token)
			
			log(fmt.Sprintf("Connection from %s closed", clientConn.RemoteAddr()))
		}(conn)
	}
}

// handleProxyConnection handles a proxy connection with message analysis
func (bt *BatchTester) handleProxyConnection(clientConn, serverConn net.Conn, token string) {
	var clientReader io.Reader = clientConn
	var serverWriter io.Writer = serverConn
	var serverReader io.Reader = serverConn
	var clientWriter io.Writer = clientConn
	
	// Setup encryption if token is provided
	if token != "" {
		key := make([]byte, 32)
		copy(key, []byte(token))
		
		// Setup client-side encryption
		clientCrypto, err := NewCryptoReadWriter(
			struct {
				io.Reader
				io.Writer
				io.Closer
			}{clientReader, clientWriter, clientConn},
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
			}{serverReader, serverWriter, serverConn},
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
		bt.forwardWithParsing(clientReader, serverWriter, "frpc -> frps")
	}()
	
	// Server to client (simple forwarding)
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(clientWriter, serverReader)
	}()
	
	// Wait for either direction to finish
	<-done
}

// forwardWithParsing forwards data while parsing frp messages
func (bt *BatchTester) forwardWithParsing(src io.Reader, dst io.Writer, direction string) {
	buf := make([]byte, 32*1024)
	
	for {
		// Try to read a complete message
		if n, err := io.ReadFull(src, buf[:9]); err != nil {
			if err != io.EOF {
				log(fmt.Sprintf("Error reading message header (%s): %v", direction, err))
			}
			return
		} else if n != 9 {
			log(fmt.Sprintf("Incomplete message header (%s): got %d bytes", direction, n))
			return
		}
		
		msgType := buf[0]
		length := binary.BigEndian.Uint64(buf[1:9])
		
		if length > 10*1024*1024 { // 10MB limit
			log(fmt.Sprintf("Message too large (%s): %d bytes", direction, length))
			return
		}
		
		// Read message content
		content := make([]byte, length)
		if n, err := io.ReadFull(src, content); err != nil {
			log(fmt.Sprintf("Error reading message content (%s): %v", direction, err))
			return
		} else if uint64(n) != length {
			log(fmt.Sprintf("Incomplete message content (%s): expected %d, got %d", direction, length, n))
			return
		}
		
		// Parse and log specific message types
		bt.parseAndLogMessage(msgType, content, direction)
		
		// Forward the complete message
		if _, err := dst.Write(buf[:9]); err != nil {
			log(fmt.Sprintf("Error forwarding message header (%s): %v", direction, err))
			return
		}
		if _, err := dst.Write(content); err != nil {
			log(fmt.Sprintf("Error forwarding message content (%s): %v", direction, err))
			return
		}
	}
}

// parseAndLogMessage parses and logs specific message types
func (bt *BatchTester) parseAndLogMessage(msgType byte, content []byte, direction string) {
	switch msgType {
	case TypeLogin:
		var msg Login
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (Login):\n%s", direction, 
				bt.sanitizeOutput(string(prettyJSON))))
		}
		
	case TypeNewProxy:
		var msg NewProxy
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (NewProxy):\n%s", direction, 
				bt.sanitizeOutput(string(prettyJSON))))
		}
		
	case TypeLoginResp:
		var msg LoginResp
		if err := json.Unmarshal(content, &msg); err == nil {
			prettyJSON, _ := json.MarshalIndent(msg, "", "  ")
			log(fmt.Sprintf("[DECODE] %s (LoginResp):\n%s", direction, 
				bt.sanitizeOutput(string(prettyJSON))))
		}
	}
}

// sanitizeOutput removes potentially sensitive information from output
func (bt *BatchTester) sanitizeOutput(input string) string {
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

// downloadLatestFrpRelease downloads the latest frp release from GitHub
func downloadLatestFrpRelease(targetDir string) error {
	log("Fetching latest frp release info...")
	
	// Get latest release info
	resp, err := http.Get("https://api.github.com/repos/fatedier/frp/releases/latest")
	if err != nil {
		return fmt.Errorf("failed to get release info: %v", err)
	}
	defer resp.Body.Close()
	
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release info: %v", err)
	}
	
	log(fmt.Sprintf("Latest frp version: %s", release.TagName))
	
	// Download archives for each platform
	platforms := []struct {
		goos, goarch, archive string
	}{
		{"linux", "amd64", "linux_amd64.tar.gz"},
		{"linux", "386", "linux_386.tar.gz"},
		{"linux", "arm64", "linux_arm64.tar.gz"},
		{"linux", "arm", "linux_arm.tar.gz"},
		{"windows", "amd64", "windows_amd64.zip"},
		{"windows", "386", "windows_386.zip"},
		{"windows", "arm64", "windows_arm64.zip"},
		{"darwin", "amd64", "darwin_amd64.tar.gz"},
		{"darwin", "arm64", "darwin_arm64.tar.gz"},
	}
	
	for _, platform := range platforms {
		archiveName := fmt.Sprintf("frp_%s_%s", release.TagName, platform.archive)
		
		// Find the asset
		var downloadURL string
		for _, asset := range release.Assets {
			if asset.Name == archiveName {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		
		if downloadURL == "" {
			log(fmt.Sprintf("Warning: Archive not found for %s/%s", platform.goos, platform.goarch))
			continue
		}
		
		log(fmt.Sprintf("Downloading %s...", archiveName))
		
		if err := downloadAndExtractFrpc(downloadURL, targetDir, platform.goos, platform.goarch, strings.HasSuffix(archiveName, ".zip")); err != nil {
			log(fmt.Sprintf("Failed to download %s: %v", archiveName, err))
			continue
		}
	}
	
	return nil
}

// downloadAndExtractFrpc downloads and extracts frpc binary from archive
func downloadAndExtractFrpc(url, targetDir, goos, goarch string, isZip bool) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var binaryName string
	if goos == "windows" {
		binaryName = "frpc.exe"
	} else {
		binaryName = "frpc"
	}
	
	outputName := fmt.Sprintf("frpc_%s_%s", goos, goarch)
	if goos == "windows" {
		outputName += ".exe"
	}
	outputPath := filepath.Join(targetDir, outputName)
	
	if isZip {
		return fmt.Errorf("ZIP extraction not implemented yet")
	} else {
		// Handle tar.gz
		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gzr.Close()
		
		tr := tar.NewReader(gzr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			
			if filepath.Base(header.Name) == binaryName {
				outFile, err := os.Create(outputPath)
				if err != nil {
					return err
				}
				defer outFile.Close()
				
				if _, err := io.Copy(outFile, tr); err != nil {
					return err
				}
				
				if err := os.Chmod(outputPath, 0755); err != nil {
					return err
				}
				
				log(fmt.Sprintf("Extracted %s", outputName))
				return nil
			}
		}
	}
	
	return fmt.Errorf("frpc binary not found in archive")
}

// log prints a timestamped log message
func log(message string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
}

func main() {
	var (
		mode           = flag.String("mode", "batch", "Operation mode: 'batch' or 'proxy'")
		serverAddr     = flag.String("server", "", "FRP server address (required)")
		serverPort     = flag.Int("port", 7000, "FRP server port")
		token          = flag.String("token", "", "FRP authentication token")
		proxyName      = flag.String("proxy-name", "test", "Proxy name prefix")
		proxyType      = flag.String("proxy-type", "tcp", "Proxy type (tcp, http, https)")
		localPort      = flag.Int("local-port", 8080, "Local port base (will increment for each instance)")
		remotePort     = flag.Int("remote-port", 0, "Remote port base (for TCP proxies)")
		customDomain   = flag.String("custom-domain", "", "Custom domain for HTTP proxies")
		subDomain      = flag.String("subdomain", "", "Subdomain prefix for HTTP proxies")
		httpUser       = flag.String("http-user", "", "HTTP authentication username")
		httpPwd        = flag.String("http-pwd", "", "HTTP authentication password")
		count          = flag.Int("count", 1, "Number of frpc instances to run")
		duration       = flag.Duration("duration", 30*time.Second, "Test duration")
		timeout        = flag.Duration("timeout", 10*time.Second, "Proxy connection timeout")
		outputFormat   = flag.String("output", "text", "Output format: text, json")
		downloadBinaries = flag.Bool("download-binaries", false, "Download latest frpc binaries")
		versionFlag    = flag.Bool("version", false, "Show version information")
	)
	
	flag.Parse()
	
	if *versionFlag {
		fmt.Printf("FRP Batch Tester\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("FRP Version: %s\n", FrpVersion)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}
	
	if *downloadBinaries {
		if err := downloadLatestFrpRelease("./binaries"); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to download binaries: %v\n", err)
			os.Exit(1)
		}
		log("Binary download completed")
		return
	}
	
	if *serverAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: --server is required\n")
		flag.Usage()
		os.Exit(1)
	}
	
	config := &TestConfig{
		ServerAddr:     *serverAddr,
		ServerPort:     *serverPort,
		Token:          *token,
		ProxyName:      *proxyName,
		ProxyType:      *proxyType,
		LocalPort:      *localPort,
		RemotePort:     *remotePort,
		CustomDomain:   *customDomain,
		SubDomain:      *subDomain,
		HTTPUser:       *httpUser,
		HTTPPwd:        *httpPwd,
		TestDuration:   *duration,
		ProxyTimeout:   *timeout,
		EnableAnalysis: *mode == "proxy",
		OutputFormat:   *outputFormat,
	}
	
	log("Starting FRP Batch Tester")
	log(fmt.Sprintf("Version: %s (Build: %s)", Version, BuildTime))
	log(fmt.Sprintf("Mode: %s", *mode))
	
	tester, err := NewBatchTester(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create batch tester: %v\n", err)
		os.Exit(1)
	}
	defer tester.Cleanup()
	
	if *mode == "proxy" {
		// Run proxy analysis mode
		if err := tester.RunProxyAnalysis(); err != nil {
			fmt.Fprintf(os.Stderr, "Proxy analysis failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Run batch test mode
		if err := tester.RunBatchTest(*count); err != nil {
			fmt.Fprintf(os.Stderr, "Batch test failed: %v\n", err)
			os.Exit(1)
		}
	}
}
