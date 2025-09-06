package main

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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

// ScanResult represents a scan result
type ScanResult struct {
	IP       string
	Port     int
	Success  bool
	RunID    string
	Duration time.Duration
	Error    string
}

// Scanner represents the main scanner
type Scanner struct {
	token       string
	concurrency int
	delay       time.Duration
	timeout     time.Duration
	results     []ScanResult
	mu          sync.Mutex
	wg          sync.WaitGroup
	tempDir     string
}

func main() {
	// Add defer to prevent immediate exit in Windows
	defer func() {
		if runtime.GOOS == "windows" {
			fmt.Println("\n" + strings.Repeat("═", 60))
			fmt.Println("Press Enter to exit...")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
	}()

	printBanner()

	// Get user input
	target, token, concurrency, delay := getUserInput()

	scanner := &Scanner{
		token:       token,
		concurrency: concurrency,
		delay:       delay,
		timeout:     15 * time.Second, // Increased timeout
	}

	// Create temp directory
	var err error
	scanner.tempDir, err = os.MkdirTemp("", "frp-scanner-*")
	if err != nil {
		log("❌ Failed to create temp directory: " + err.Error())
		return
	}
	defer os.RemoveAll(scanner.tempDir)

	// Parse target and get IP list
	ips, err := parseTarget(target)
	if err != nil {
		log("❌ Invalid target: " + err.Error())
		return
	}

	log(fmt.Sprintf("🎯 Target: %s (%d IPs)", target, len(ips)))
	log(fmt.Sprintf("⚙️ Concurrency: %d, Delay: %v", concurrency, delay))
	if token == "" {
		log("🔑 Token: [No token - testing without authentication]")
	} else {
		log(fmt.Sprintf("🔑 Token: %s", maskToken(token)))
	}

	// Start scanning
	scanner.scan(ips)

	// Show results
	scanner.showResults()
}

func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    FRP Server Scanner                        ║")
	fmt.Println("║                  Batch FRP Testing Tool                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Version: %-10s Build: %-15s FRP: %-10s ║\n", Version, BuildTime, FrpVersion)
	fmt.Printf("║ Platform: %s/%s                                     ║\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func getUserInput() (string, string, int, time.Duration) {
	reader := bufio.NewReader(os.Stdin)

	// Get target
	fmt.Print("🎯 Enter target (IP address or CIDR): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	
	if target == "" {
		log("❌ Target cannot be empty")
		if runtime.GOOS == "windows" {
			fmt.Println("Press Enter to exit...")
			reader.ReadString('\n')
		}
		os.Exit(1)
	}

	// Get token (optional)
	fmt.Print("🔑 Enter FRP token (press Enter for no token): ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	// Get concurrency
	fmt.Print("🚀 Enter concurrency (default 10): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrencyStr = strings.TrimSpace(concurrencyStr)
	
	concurrency := 10
	if concurrencyStr != "" {
		if c, err := strconv.Atoi(concurrencyStr); err == nil && c > 0 && c <= 100 {
			concurrency = c
		} else {
			log("⚠️ Invalid concurrency, using default: 10")
		}
	}

	// Get delay
	fmt.Print("⏱️ Enter delay between requests in ms (default 100): ")
	delayStr, _ := reader.ReadString('\n')
	delayStr = strings.TrimSpace(delayStr)
	
	delay := 100 * time.Millisecond
	if delayStr != "" {
		if d, err := strconv.Atoi(delayStr); err == nil && d >= 0 {
			delay = time.Duration(d) * time.Millisecond
		} else {
			log("⚠️ Invalid delay, using default: 100ms")
		}
	}

	fmt.Println()
	return target, token, concurrency, delay
}

func parseTarget(target string) ([]string, error) {
	// Check if it's a CIDR
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}

	// Single IP address
	if net.ParseIP(target) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", target)
	}

	return []string{target}, nil
}

func parseCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and larger subnets
	ones, _ := ipNet.Mask.Size()
	if ones < 31 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1] // Remove first and last
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *Scanner) scan(ips []string) {
	log(fmt.Sprintf("🚀 Starting scan of %d IPs...", len(ips)))
	
	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, s.concurrency)
	s.results = make([]ScanResult, 0, len(ips))

	startTime := time.Now()

	// Progress tracking
	completed := 0

	for i, ip := range ips {
		s.wg.Add(1)
		
		go func(ip string, index int) {
			defer s.wg.Done()
			
			// Wait for semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Add delay between requests
			if s.delay > 0 && index > 0 {
				time.Sleep(s.delay)
			}

			result := s.testSingleIP(ip)
			
			s.mu.Lock()
			s.results = append(s.results, result)
			completed++
			
			if result.Success {
				log(fmt.Sprintf("✅ [%d/%d] %s - SUCCESS (RunID: %s, %v)", 
					completed, len(ips), ip, result.RunID, result.Duration))
			} else {
				log(fmt.Sprintf("❌ [%d/%d] %s - FAILED (%s)", 
					completed, len(ips), ip, result.Error))
			}
			s.mu.Unlock()
		}(ip, i)
	}

	s.wg.Wait()
	
	elapsed := time.Since(startTime)
	log(fmt.Sprintf("⏱️ Scan completed in %v", elapsed))
}

func (s *Scanner) testSingleIP(ip string) ScanResult {
	start := time.Now()
	result := ScanResult{
		IP:   ip,
		Port: 7000,
	}

	// Create frpc config
	configPath, err := s.createConfig(ip)
	if err != nil {
		result.Error = "Config creation failed: " + err.Error()
		result.Duration = time.Since(start)
		return result
	}
	defer func() {
		if err := os.Remove(configPath); err != nil {
			// Ignore cleanup errors
		}
	}()

	// Find frpc binary
	frpcPath, err := s.findFrpcBinary()
	if err != nil {
		result.Error = "FRPC not found: " + err.Error()
		result.Duration = time.Since(start)
		return result
	}

	// Run frpc with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, frpcPath, "-c", configPath)
	
	// Redirect stderr to capture all output
	output, err := cmd.CombinedOutput()
	
	result.Duration = time.Since(start)
	
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "Connection timeout"
		return result
	}

	outputStr := string(output)

	// Debug output for troubleshooting (remove in production)
	if len(outputStr) > 0 {
		// You can uncomment this for debugging
		// fmt.Printf("[DEBUG] %s output: %s\n", ip, strings.TrimSpace(outputStr))
	}

	if err != nil {
		// Parse error types for better error messages
		if strings.Contains(outputStr, "connection refused") {
			result.Error = "Connection refused"
		} else if strings.Contains(outputStr, "timeout") {
			result.Error = "Connection timeout"
		} else if strings.Contains(outputStr, "login to server failed") {
			result.Error = "Login failed"
		} else if strings.Contains(outputStr, "authentication failed") {
			result.Error = "Auth failed"
		} else if strings.Contains(outputStr, "no such host") {
			result.Error = "Host not found"
		} else if strings.Contains(outputStr, "network is unreachable") {
			result.Error = "Network unreachable"
		} else if strings.Contains(outputStr, "i/o timeout") {
			result.Error = "I/O timeout"
		} else if strings.Contains(outputStr, "connection reset") {
			result.Error = "Connection reset"
		} else {
			result.Error = "Connection failed"
		}
		return result
	}

	// Parse output for success - enhanced detection
	if runID := extractRunID(outputStr); runID != "" {
		result.Success = true
		result.RunID = runID
	} else {
		// Check for other success indicators
		successIndicators := []string{
			"login to server success",
			"start tunnel",
			"proxy added",
			"start frpc success",
		}
		
		hasSuccess := false
		for _, indicator := range successIndicators {
			if strings.Contains(strings.ToLower(outputStr), strings.ToLower(indicator)) {
				hasSuccess = true
				break
			}
		}
		
		if hasSuccess {
			result.Success = true
			result.RunID = "connected"
		} else {
			result.Error = "No success indicator found"
			// Still try to classify the error
			if strings.Contains(outputStr, "connection refused") {
				result.Error = "Connection refused"
			} else if strings.Contains(outputStr, "timeout") {
				result.Error = "Connection timeout"
			} else if strings.Contains(outputStr, "login to server failed") {
				result.Error = "Login failed"
			} else if strings.Contains(outputStr, "authentication failed") {
				result.Error = "Auth failed"
			}
		}
	}

	return result
}

func (s *Scanner) createConfig(serverIP string) (string, error) {
	// Create config with or without token
	var config string
	if s.token == "" {
		// Config without token
		config = fmt.Sprintf(`[common]
server_addr = %s
server_port = 7000
login_fail_exit = true
log_level = info

[scanner-test]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 0
`, serverIP)
	} else {
		// Config with token
		config = fmt.Sprintf(`[common]
server_addr = %s
server_port = 7000
token = %s
login_fail_exit = true
log_level = info

[scanner-test]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 0
`, serverIP, s.token)
	}

	configPath := filepath.Join(s.tempDir, fmt.Sprintf("frpc_%s.toml", strings.ReplaceAll(serverIP, ".", "_")))
	return configPath, os.WriteFile(configPath, []byte(config), 0644)
}

func (s *Scanner) findFrpcBinary() (string, error) {
	// Try embedded binary first (for release builds)
	if embeddedPath, err := s.extractEmbeddedBinary(); err == nil {
		return embeddedPath, nil
	}

	// Try local files (for development)
	localPaths := []string{
		"frpc",
		"frpc.exe", 
		"./frpc",
		"./frpc.exe",
	}

	for _, path := range localPaths {
		if _, err := os.Stat(path); err == nil {
			absPath, _ := filepath.Abs(path)
			log(fmt.Sprintf("🔧 Using local frpc: %s", absPath))
			return absPath, nil
		}
	}

	return "", fmt.Errorf("frpc binary not found. Please place frpc/frpc.exe in the same directory or use a build with embedded binaries")
}

func (s *Scanner) extractEmbeddedBinary() (string, error) {
	// Determine the binary name based on current platform
	var binaryName string
	switch runtime.GOOS {
	case "windows":
		binaryName = fmt.Sprintf("frpc_%s_%s.exe", runtime.GOOS, runtime.GOARCH)
	default:
		binaryName = fmt.Sprintf("frpc_%s_%s", runtime.GOOS, runtime.GOARCH)
	}

	// Try to read the binary from embedded files
	data, err := embeddedBinaries.ReadFile("binaries/" + binaryName)
	if err != nil {
		return "", fmt.Errorf("embedded frpc binary not found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Check if the binary data looks valid
	if len(data) < 1000 {
		return "", fmt.Errorf("embedded frpc binary seems corrupted (too small: %d bytes)", len(data))
	}

	// Write to temp file
	frpcPath := filepath.Join(s.tempDir, "frpc")
	if runtime.GOOS == "windows" {
		frpcPath += ".exe"
	}

	if err := os.WriteFile(frpcPath, data, 0755); err != nil {
		return "", fmt.Errorf("failed to write frpc binary: %v", err)
	}

	log(fmt.Sprintf("🔧 Using embedded frpc: %s (%d bytes)", frpcPath, len(data)))
	return frpcPath, nil
}

func extractRunID(output string) string {
	// Enhanced patterns to match various FRP success responses
	patterns := []string{
		`get run id \[([a-f0-9]+)\]`,
		`run id \[([a-f0-9]+)\]`,
		`login to server success.*?get run id \[([a-f0-9]+)\]`,
		`login to server success.*?run id \[([a-f0-9]+)\]`,
		`\[.*?\] \[.*?\] \[([a-f0-9]+)\] login to server success`,
		`runId=([a-f0-9]+)`,
		`run_id:([a-f0-9]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern) // Case insensitive
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func (s *Scanner) showResults() {
	fmt.Println()
	log("📊 Scan Results Summary")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if len(s.results) == 0 {
		fmt.Println("⚠️ No results to display")
		return
	}

	// Sort results by IP
	sort.Slice(s.results, func(i, j int) bool {
		return ipToInt(s.results[i].IP) < ipToInt(s.results[j].IP)
	})

	successful := []ScanResult{}
	failed := []ScanResult{}

	for _, result := range s.results {
		if result.Success {
			successful = append(successful, result)
		} else {
			failed = append(failed, result)
		}
	}

	// Show successful results
	if len(successful) > 0 {
		fmt.Printf("✅ Successful Connections (%d):\n", len(successful))
		fmt.Println("┌─────────────────┬──────┬─────────────────┬──────────────┐")
		fmt.Println("│ IP Address      │ Port │ Run ID          │ Duration     │")
		fmt.Println("├─────────────────┼──────┼─────────────────┼──────────────┤")
		
		for _, result := range successful {
			fmt.Printf("│ %-15s │ %-4d │ %-15s │ %-12v │\n",
				result.IP, result.Port, result.RunID, result.Duration.Round(time.Millisecond))
		}
		fmt.Println("└─────────────────┴──────┴─────────────────┴──────────────┘")
		fmt.Println()

		// Save successful results to file
		s.saveResults(successful)
	}

	// Show failed results summary
	if len(failed) > 0 {
		fmt.Printf("❌ Failed Connections (%d):\n", len(failed))
		
		// Group by error
		errorGroups := make(map[string][]string)
		for _, result := range failed {
			errorGroups[result.Error] = append(errorGroups[result.Error], result.IP)
		}

		for errorMsg, ips := range errorGroups {
			fmt.Printf("   %s: %d IPs\n", errorMsg, len(ips))
			if len(ips) <= 5 {
				fmt.Printf("     %s\n", strings.Join(ips, ", "))
			} else {
				fmt.Printf("     %s ... and %d more\n", strings.Join(ips[:5], ", "), len(ips)-5)
			}
		}
		fmt.Println()
	}

	// Statistics
	total := len(s.results)
	successRate := float64(len(successful)) / float64(total) * 100
	
	fmt.Printf("📈 Statistics:\n")
	fmt.Printf("   Total tested: %d\n", total)
	fmt.Printf("   Successful: %d (%.1f%%)\n", len(successful), successRate)
	fmt.Printf("   Failed: %d (%.1f%%)\n", len(failed), 100-successRate)
	
	if len(successful) > 0 {
		var totalDuration time.Duration
		for _, result := range successful {
			totalDuration += result.Duration
		}
		avgDuration := totalDuration / time.Duration(len(successful))
		fmt.Printf("   Avg response time: %v\n", avgDuration.Round(time.Millisecond))
	}
	
	fmt.Println()
}

func (s *Scanner) saveResults(successful []ScanResult) {
	if len(successful) == 0 {
		log("ℹ️ No successful results to save")
		return
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log("⚠️ Failed to get current directory: " + err.Error())
		cwd = "."
	}

	filename := fmt.Sprintf("frp_servers_%s.txt", time.Now().Format("20060102_150405"))
	fullPath := filepath.Join(cwd, filename)
	
	content := fmt.Sprintf("# FRP Server Scan Results\n")
	content += fmt.Sprintf("# Scanned at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if s.token == "" {
		content += fmt.Sprintf("# Token: [No token used]\n")
	} else {
		content += fmt.Sprintf("# Token: %s\n", maskToken(s.token))
	}
	content += fmt.Sprintf("# Total successful: %d\n\n", len(successful))
	
	for _, result := range successful {
		content += fmt.Sprintf("%-15s:%-4d  # RunID: %s, Duration: %v\n",
			result.IP, result.Port, result.RunID, result.Duration.Round(time.Millisecond))
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		log("⚠️ Failed to save results to file: " + err.Error())
	} else {
		log("💾 Results saved to: " + fullPath)
	}
}

func ipToInt(ip string) uint32 {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0
	}
	
	parsedIP = parsedIP.To4()
	if parsedIP == nil {
		return 0
	}
	
	return uint32(parsedIP[0])<<24 + uint32(parsedIP[1])<<16 + uint32(parsedIP[2])<<8 + uint32(parsedIP[3])
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}

func log(msg string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}
