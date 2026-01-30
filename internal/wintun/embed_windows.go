//go:build windows

// Package wintun 提供 Windows 平台的 Wintun DLL 嵌入和加载功能
package wintun

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed wintun_amd64.dll
var wintunAMD64 []byte

//go:embed wintun_arm64.dll
var wintunARM64 []byte

var (
	extractOnce sync.Once
	extractErr  error
	dllPath     string
)

// ExtractDLL 解压嵌入的 wintun.dll 到本地缓存目录
// 返回 DLL 所在目录的路径
func ExtractDLL() (string, error) {
	extractOnce.Do(func() {
		dllPath, extractErr = doExtract()
	})
	return dllPath, extractErr
}

func doExtract() (string, error) {
	// 选择正确架构的 DLL
	var dllData []byte
	switch runtime.GOARCH {
	case "amd64":
		dllData = wintunAMD64
	case "arm64":
		dllData = wintunARM64
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	if len(dllData) == 0 {
		return "", fmt.Errorf("wintun.dll not embedded for architecture: %s", runtime.GOARCH)
	}

	// 尝试按优先级选择 DLL 释放目录
	// 1. 可执行文件目录（如果可写）
	// 2. %LOCALAPPDATA%\hysterguard\
	// 3. %TEMP%\hysterguard\

	candidateDirs := []string{}

	// 优先尝试可执行文件目录
	if exePath, err := os.Executable(); err == nil {
		candidateDirs = append(candidateDirs, filepath.Dir(exePath))
	}

	// 备选：LocalAppData
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		candidateDirs = append(candidateDirs, filepath.Join(localAppData, "hysterguard"))
	}

	// 备选：临时目录
	candidateDirs = append(candidateDirs, filepath.Join(os.TempDir(), "hysterguard"))

	var lastErr error
	for _, dir := range candidateDirs {
		dllPath := filepath.Join(dir, "wintun.dll")

		// 确保目录存在
		if err := os.MkdirAll(dir, 0755); err != nil {
			lastErr = fmt.Errorf("failed to create directory %s: %w", dir, err)
			continue
		}

		// 检查是否需要更新（比较文件大小）
		needUpdate := true
		if info, err := os.Stat(dllPath); err == nil {
			if info.Size() == int64(len(dllData)) {
				// DLL 已存在且大小一致，直接返回
				return dir, nil
			}
		}

		if needUpdate {
			// 尝试写入 DLL 文件
			if err := os.WriteFile(dllPath, dllData, 0644); err != nil {
				lastErr = fmt.Errorf("failed to write wintun.dll to %s: %w", dir, err)
				continue
			}
		}

		return dir, nil
	}

	return "", fmt.Errorf("unable to extract wintun.dll to any directory: %w", lastErr)
}

// SetDLLDirectory 设置 DLL 搜索目录
// 必须在调用任何 wintun 函数之前调用
func SetDLLDirectory(dir string) error {
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("SetDllDirectoryW")
	r1, _, err := proc.Call(uintptr(unsafe.Pointer(dirPtr)))
	if r1 == 0 {
		return err
	}
	return nil
}

// EnsureLoaded 确保 wintun.dll 已解压并设置好搜索路径
// 这是客户端启动时应该调用的主函数
func EnsureLoaded() error {
	dir, err := ExtractDLL()
	if err != nil {
		return fmt.Errorf("failed to extract wintun.dll: %w", err)
	}

	// 方法1: 修改 PATH 环境变量
	currentPath := os.Getenv("PATH")
	os.Setenv("PATH", dir+";"+currentPath)

	// 方法2: 使用 SetDllDirectory (可选，作为备用)
	// SetDLLDirectory(dir)

	return nil
}
