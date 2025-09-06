package main

import (
	"bufio"
	"context"
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
	"sync"
	"time"
)

const (
	FRP_PORT         = 7000
	TEST_TIMEOUT     = 5 * time.Second // 5秒超时
	CONCURRENT_LIMIT = 5               // 并发数量
	BATCH_DELAY      = 100             // 批次间延迟(毫秒)
)

type TestResult struct {
	IP       string
	Status   string
	RunID    string
	Duration time.Duration
	Error    string
}

type FrpTester struct {
	frpcPath    string
	configPath  string
	results     []TestResult
	resultMutex sync.Mutex
	workerPaths []string // 多个frpc副本路径
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

	tester := &FrpTester{
		frpcPath:   frpcPath,
		configPath: configPath,
		results:    make([]TestResult, 0),
	}

	// 创建多个frpc副本
	if err := tester.createWorkerCopies(); err != nil {
		return nil, fmt.Errorf("failed to create worker copies: %v", err)
	}

	return tester, nil
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

func (ft *FrpTester) createWorkerCopies() error {
	ft.workerPaths = make([]string, CONCURRENT_LIMIT)
	
	for i := 0; i < CONCURRENT_LIMIT; i++ {
		// 为每个worker创建frpc副本
		workerName := fmt.Sprintf("frpc_worker_%d", i+1)
		if strings.HasSuffix(ft.frpcPath, ".exe") {
			workerName += ".exe"
		}
		
		workerPath := filepath.Join(filepath.Dir(ft.frpcPath), workerName)
		
		// 复制frpc文件
		if err := copyFile(ft.frpcPath, workerPath); err != nil {
			return fmt.Errorf("failed to copy frpc for worker %d: %v", i+1, err)
		}
		
		// 设置执行权限 (Unix系统)
		if err := os.Chmod(workerPath, 0755); err != nil {
			log.Printf("[WARN] Failed to set execute permission for %s: %v", workerPath, err)
		}
		
		ft.workerPaths[i] = workerPath
		log.Printf("[INFO] Created worker %d: %s", i+1, workerPath)
	}
	
	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func (ft *FrpTester) cleanup() {
	// 清理worker副本
	for _, workerPath := range ft.workerPaths {
		if err := os.Remove(workerPath); err != nil {
			log.Printf("[WARN] Failed to remove worker file %s: %v", workerPath, err)
		}
	}
}

func (ft *FrpTester) TestSingleIP(ip string, workerID int) TestResult {
	result := TestResult{
		IP:     ip,
		Status: "Failed",
	}

	startTime := time.Now()
	workerPath := ft.workerPaths[workerID%len(ft.workerPaths)]

	log.Printf("[TEST] Worker %d testing %s:%d", workerID, ip, FRP_PORT)

	// 创建临时配置文件
	tempConfig, err := ft.createTempConfig(ip, workerID)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create temp config: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	defer os.Remove(tempConfig)

	// 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), TEST_TIMEOUT)
	defer cancel()

	// 执行frpc命令
	cmd := exec.CommandContext(ctx, workerPath, "-c", tempConfig)
	
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
	doneChan := make(chan bool, 1)

	// 读取stdout和stderr
	go ft.readOutput(stdout, outputChan)
	go ft.readOutput(stderr, outputChan)

	// 监控输出中的成功/失败信息
	go func() {
		for {
			select {
			case line := <-outputChan:
				log.Printf("[OUTPUT] Worker %d (%s): %s", workerID, ip, line)
				
				// 检查成功标志
				if runID := ft.extractRunID(line); runID != "" {
					result.Status = "Success"
					result.RunID = runID
					select {
					case doneChan <- true:
					default:
					}
					return
				}
				
				// 检查错误标志
				if ft.isErrorLine(line) {
					result.Error = line
					select {
					case doneChan <- true:
					default:
					}
					return
				}
				
			case <-ctx.Done():
				result.Error = "Connection timeout (5s)"
				select {
				case doneChan <- true:
				default:
				}
				return
			}
		}
	}()

	// 等待结果或超时
	select {
	case <-doneChan:
		// 测试完成
	case <-ctx.Done():
		// 超时
		if result.Error == "" {
			result.Error = "Connection timeout (5s)"
		}
	}

	// 确保进程被终止
	if cmd.Process != nil {
		cmd.Process.Kill()
	}

	result.Duration = time.Since(startTime)
	log.Printf("[RESULT] Worker %d - %s: %s (%.2fs)", workerID, ip, result.Status, result.Duration.Seconds())
	
	return result
}

func (ft *FrpTester) readOutput(reader io.ReadCloser, outputChan chan<- string) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		select {
		case outputChan <- scanner.Text():
		default:
			// 防止阻塞
		}
	}
}

func (ft *FrpTester) extractRunID(line string) string {
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
		"connect: connection refused",
		"i/o timeout",
	}
	
	lowerLine := strings.ToLower(line)
	for _, keyword := range errorKeywords {
		if strings.Contains(lowerLine, keyword) {
			return true
		}
	}
	
	return false
}

func (ft *FrpTester) createTempConfig(serverIP string, workerID int) (string, error) {
	// 读取原始配置文件
	originalConfig, err := ioutil.ReadFile(ft.configPath)
	if err != nil {
		return "", err
	}

	// 创建临时配置文件
	tempFile, err := ioutil.TempFile("", fmt.Sprintf("frpc_test_worker_%d_*.toml", workerID))
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

	// 为每个worker修改代理名称，避免冲突
	configContent = ft.modifyProxyNames(configContent, workerID)

	// 写入临时文件
	err = ioutil.WriteFile(tempFile.Name(), []byte(configContent), 0644)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

func (ft *FrpTester) modifyProxyNames(configContent string, workerID int) string {
	// 修改代理名称以避免冲突
	proxyNamePattern := regexp.MustCompile(`(\[.*?\])`)
	configContent = proxyNamePattern.ReplaceAllStringFunc(configContent, func(match string) string {
		if strings.Contains(match, "common") {
			return match // 保持common段不变
		}
		// 为代理段添加worker标识
		return strings.TrimSuffix(match, "]") + fmt.Sprintf("_w%d]", workerID)
	})

	// 修改name字段
	namePattern := regexp.MustCompile(`name\s*=\s*"([^"]*)"`)
	configContent = namePattern.ReplaceAllStringFunc(configContent, func(match string) string {
		return regexp.MustCompile(`"([^"]*)"`)ReplaceAllStringFunc(match, func(name string) string {
			return fmt.Sprintf(`"%s_w%d"`, strings.Trim(name, `"`), workerID)
		})
	})

	return configContent
}

func (ft *FrpTester) TestCIDRConcurrent(cidr string) error {
	log.Printf("[INFO] Starting concurrent CIDR scan: %s", cidr)

	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %v", err)
	}

	// 生成IP列表
	ips := ft.generateIPList(ipNet)
	log.Printf("[INFO] Found %d IPs to test with %d concurrent workers", len(ips), CONCURRENT_LIMIT)

	// 创建任务通道
	ipChan := make(chan string, len(ips))
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// 启动并发worker
	var wg sync.WaitGroup
	for i := 0; i < CONCURRENT_LIMIT; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for ip := range ipChan {
				result := ft.TestSingleIP(ip, workerID)
				
				// 安全地添加结果
				ft.resultMutex.Lock()
				ft.results = append(ft.results, result)
				progress := len(ft.results)
				total := len(ips)
				ft.resultMutex.Unlock()
				
				log.Printf("[PROGRESS] Completed %d/%d (%.1f%%)", 
					progress, total, float64(progress)/float64(total)*100)
				
				// 添加小延迟避免过载
				time.Sleep(time.Duration(BATCH_DELAY) * time.Millisecond)
			}
		}(i)
	}

	// 等待所有worker完成
	wg.Wait()
	log.Printf("[INFO] All tests completed")

	return nil
}

func (ft *FrpTester) TestCIDR(cidr string) error {
	return ft.TestCIDRConcurrent(cidr)
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
	fmt.Println("=== FRP Server Testing Tool (Concurrent Version) ===")
	fmt.Printf("Concurrent workers: %d, Timeout: %v\n", CONCURRENT_LIMIT, TEST_TIMEOUT)
	fmt.Println()

	// 初始化测试器
	tester, err := NewFrpTester()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	// 确保清理worker副本
	defer tester.cleanup()

	// 获取用户输入
	input := getUserInput()
	if input == "" {
		log.Fatalf("[FATAL] No input provided")
	}

	// 记录开始时间
	startTime := time.Now()

	// 判断输入类型并执行测试
	if isValidCIDR(input) {
		log.Printf("[INFO] Detected CIDR input: %s", input)
		err = tester.TestCIDR(input)
	} else if isValidIP(input) {
		log.Printf("[INFO] Detected single IP input: %s", input)
		result := tester.TestSingleIP(input, 0)
		tester.results = []TestResult{result}
	} else {
		log.Fatalf("[FATAL] Invalid input format. Please enter a valid IP or CIDR")
	}

	if err != nil {
		log.Fatalf("[FATAL] Test error: %v", err)
	}

	// 显示总耗时
	totalDuration := time.Since(startTime)
	fmt.Printf("\n[INFO] Total test duration: %v\n", totalDuration)

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
