package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	FRP_PORT = 7000
	DELAY_MS = 1000 // 每次测试间隔1秒
)

type TestResult struct {
	IP       string
	Status   string
	RunID    string
	Duration time.Duration
	Error    string
}

type FrpTester struct {
	frpcPath   string
	configPath string
	results    []TestResult
}

func NewFrpTester() (*FrpTester, error) {
	// 查找frpc程序
	frpcPath := findFrpcExecutable()
	if frpcPath == "" {
		return nil, fmt.Errorf("frpc executable not found in current directory")
	}

	// 查找配置文件
	configPath := findConfigFile()
	if configPath == "" {
		return nil, fmt.Errorf("frpc configuration file not found in current directory")
	}

	log.Printf("[INFO] Found frpc: %s", frpcPath)
	log.Printf("[INFO] Found config: %s", configPath)

	return &FrpTester{
		frpcPath:   frpcPath,
		configPath: configPath,
		results:    make([]TestResult, 0),
	}, nil
}

func findFrpcExecutable() string {
	candidates := []string{"frpc", "frpc.exe", "./frpc", "./frpc.exe"}
	
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func findConfigFile() string {
	candidates := []string{"frpc.toml", "frpc.ini", "frpc.yaml", "frpc.yml"}
	
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func (ft *FrpTester) TestSingleIP(ip string) TestResult {
	result := TestResult{
		IP:     ip,
		Status: "Failed",
	}

	startTime := time.Now()

	log.Printf("[TEST] Testing frps at %s:%d", ip, FRP_PORT)

	// 创建临时配置文件
	tempConfig, err := ft.createTempConfig(ip)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create temp config: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	defer os.Remove(tempConfig)

	// 执行frpc命令
	cmd := exec.Command(ft.frpcPath, "-c", tempConfig)
	
	// 创建管道获取输出
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create stdout pipe: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create stderr pipe: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("Failed to start frpc: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// 监控输出
	outputChan := make(chan string, 100)
	doneChan := make(chan bool)

	// 读取stdout
	go ft.readOutput(stdout, outputChan)
	// 读取stderr
	go ft.readOutput(stderr, outputChan)

	// 监控输出中的成功/失败信息
	go func() {
		timeout := time.After(10 * time.Second) // 10秒超时
		
		for {
			select {
			case line := <-outputChan:
				log.Printf("[OUTPUT] %s: %s", ip, line)
				
				// 检查成功标志
				if runID := ft.extractRunID(line); runID != "" {
					result.Status = "Success"
					result.RunID = runID
					doneChan <- true
					return
				}
				
				// 检查错误标志
				if ft.isErrorLine(line) {
					result.Error = line
					doneChan <- true
					return
				}
				
			case <-timeout:
				result.Error = "Connection timeout"
				doneChan <- true
				return
			}
		}
	}()

	// 等待结果或超时
	<-doneChan

	// 终止进程
	if cmd.Process != nil {
		cmd.Process.Kill()
	}

	result.Duration = time.Since(startTime)
	log.Printf("[RESULT] %s: %s (%.2fs)", ip, result.Status, result.Duration.Seconds())
	
	return result
}

func (ft *FrpTester) readOutput(reader io.ReadCloser, outputChan chan<- string) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		outputChan <- scanner.Text()
	}
}

func (ft *FrpTester) extractRunID(line string) string {
	// 匹配成功登录并提取run id
	patterns := []string{
		`login to server success, get run id \[([^\]]+)\]`,
		`get run id \[([^\]]+)\]`,
		`run id.*?\[([^\]]+)\]`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1]
		}
	}
	
	return ""
}

func (ft *FrpTester) isErrorLine(line string) bool {
	errorKeywords := []string{
		"connection refused",
		"no route to host",
		"timeout",
		"failed to connect",
		"login failed",
		"authentication failed",
		"error",
		"dial tcp.*refused",
	}
	
	lowerLine := strings.ToLower(line)
	for _, keyword := range errorKeywords {
		if strings.Contains(lowerLine, keyword) {
			return true
		}
	}
	
	return false
}

func (ft *FrpTester) createTempConfig(serverIP string) (string, error) {
	// 读取原始配置文件
	originalConfig, err := ioutil.ReadFile(ft.configPath)
	if err != nil {
		return "", err
	}

	// 创建临时配置文件
	tempFile, err := ioutil.TempFile("", "frpc_test_*.toml")
	if err != nil {
		return "", err
	}
	tempFile.Close()

	// 修改配置中的服务器地址
	configContent := string(originalConfig)
	
	// 替换不同格式的服务器配置
	patterns := []struct {
		pattern string
		replace string
	}{
		{`serverAddr\s*=\s*"[^"]*"`, fmt.Sprintf(`serverAddr = "%s"`, serverIP)},
		{`server_addr\s*=\s*"[^"]*"`, fmt.Sprintf(`server_addr = "%s"`, serverIP)},
		{`serverAddr\s*=\s*'[^']*'`, fmt.Sprintf(`serverAddr = "%s"`, serverIP)},
		{`server_addr\s*=\s*'[^']*'`, fmt.Sprintf(`server_addr = "%s"`, serverIP)},
		{`serverAddr:\s*"[^"]*"`, fmt.Sprintf(`serverAddr: "%s"`, serverIP)},
		{`server_addr:\s*"[^"]*"`, fmt.Sprintf(`server_addr: "%s"`, serverIP)},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(configContent) {
			configContent = re.ReplaceAllString(configContent, p.replace)
			break
		}
	}

	// 如果没有找到服务器配置，添加一个
	if !strings.Contains(configContent, serverIP) {
		configContent = fmt.Sprintf("serverAddr = \"%s\"\nserverPort = %d\n\n%s", 
			serverIP, FRP_PORT, configContent)
	}

	// 写入临时文件
	err = ioutil.WriteFile(tempFile.Name(), []byte(configContent), 0644)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

func (ft *FrpTester) TestCIDR(cidr string) error {
	log.Printf("[INFO] Starting CIDR scan: %s", cidr)

	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %v", err)
	}

	// 生成IP列表
	ips := ft.generateIPList(ipNet)
	log.Printf("[INFO] Found %d IPs to test", len(ips))

	// 测试每个IP
	for i, ip := range ips {
		log.Printf("[PROGRESS] Testing %d/%d: %s", i+1, len(ips), ip)
		
		result := ft.TestSingleIP(ip)
		ft.results = append(ft.results, result)

		// 延迟
		if i < len(ips)-1 {
			time.Sleep(time.Duration(DELAY_MS) * time.Millisecond)
		}
	}

	return nil
}

func (ft *FrpTester) generateIPList(ipNet *net.IPNet) []string {
	var ips []string
	
	// 获取网络和广播地址
	ip := ipNet.IP.Mask(ipNet.Mask)
	
	// 计算地址范围
	for {
		if !ipNet.Contains(ip) {
			break
		}
		ips = append(ips, ip.String())
		ip = ft.nextIP(ip)
	}
	
	return ips
}

func (ft *FrpTester) nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	
	return next
}

func (ft *FrpTester) SaveResults(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"IP", "Status", "Run ID", "Duration(s)", "Error"}
	writer.Write(headers)

	// 写入数据
	for _, result := range ft.results {
		record := []string{
			result.IP,
			result.Status,
			result.RunID,
			fmt.Sprintf("%.2f", result.Duration.Seconds()),
			result.Error,
		}
		writer.Write(record)
	}

	return nil
}

func (ft *FrpTester) PrintSummary() {
	successCount := 0
	for _, result := range ft.results {
		if result.Status == "Success" {
			successCount++
		}
	}

	fmt.Printf("\n=== Test Summary ===\n")
	fmt.Printf("Total tested: %d\n", len(ft.results))
	fmt.Printf("Success: %d\n", successCount)
	fmt.Printf("Failed: %d\n", len(ft.results)-successCount)
	
	if len(ft.results) > 0 {
		fmt.Printf("Success rate: %.2f%%\n", float64(successCount)/float64(len(ft.results))*100)
	}

	if successCount > 0 {
		fmt.Printf("\n=== Successful Servers ===\n")
		for _, result := range ft.results {
			if result.Status == "Success" {
				fmt.Printf("%s:%d (Run ID: %s, Duration: %.2fs)\n", 
					result.IP, FRP_PORT, result.RunID, result.Duration.Seconds())
			}
		}
	}
}

func getUserInput() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter IP address or CIDR (e.g., 192.168.1.1 or 10.10.124.0/22): ")
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func main() {
	fmt.Println("=== FRP Server Testing Tool ===")
	fmt.Println("This tool will test frp servers for successful registration")
	fmt.Println()

	// 初始化测试器
	tester, err := NewFrpTester()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// 获取用户输入
	input := getUserInput()
	if input == "" {
		log.Fatalf("[FATAL] No input provided")
	}

	// 判断输入类型并执行测试
	if isValidCIDR(input) {
		log.Printf("[INFO] Detected CIDR input: %s", input)
		err = tester.TestCIDR(input)
	} else if isValidIP(input) {
		log.Printf("[INFO] Detected single IP input: %s", input)
		result := tester.TestSingleIP(input)
		tester.results = []TestResult{result}
	} else {
		log.Fatalf("[FATAL] Invalid input format. Please enter a valid IP or CIDR")
	}

	if err != nil {
		log.Fatalf("[FATAL] Test error: %v", err)
	}

	// 显示结果摘要
	tester.PrintSummary()

	// 保存结果到CSV文件
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("frp_test_results_%s.csv", timestamp)
	
	if err := tester.SaveResults(filename); err != nil {
		log.Printf("[ERROR] Failed to save results: %v", err)
	} else {
		fmt.Printf("\n[INFO] Results saved to: %s\n", filename)
	}

	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
