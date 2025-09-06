# FRP Batch Tester

A high-performance tool for batch testing FRP (Fast Reverse Proxy) servers with concurrent processing capabilities.

## Features

- **Concurrent Testing**: Test up to 5 FRP servers simultaneously
- **Timeout Control**: 5-second timeout for each connection attempt
- **CIDR Support**: Test entire IP ranges (e.g., `10.10.124.0/22`)
- **Multiple Formats**: Export results to CSV format
- **Cross-Platform**: Support for Windows, macOS, and Linux

## Quick Start

### Method 1: Download Complete Package

1. Go to [Releases](https://github.com/yourusername/frp-batch-tester/releases)
2. Download the complete package for your platform (includes FRP binaries)
3. Extract the archive
4. Edit `frpc.toml` with your configuration
5. Run the tester

### Method 2: Build from Source

```bash
git clone https://github.com/yourusername/frp-batch-tester.git
cd frp-batch-tester
go build -o frp-tester main.go
