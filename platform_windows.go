//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procGetCurrentProcess   = kernel32.NewProc("GetCurrentProcess")
	procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procShellExecuteW       = shell32.NewProc("ShellExecuteW")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
)

const (
	tokenQuery          = 0x0008
	tokenElevationClass = 20
	swShowNormal        = 1
	mbOK                = 0x00000000
	mbIconError         = 0x00000010
)

func platformSupported() bool { return true }

// platformEnsureElevated returns true when a new elevated process was launched
// and the current process should exit.
func platformEnsureElevated() (bool, error) {
	elevated, err := windowsProcessElevated()
	if err != nil {
		return false, fmt.Errorf("检查管理员权限: %w", err)
	}
	if elevated {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("获取程序路径: %w", err)
	}
	workingDirectory, _ := os.Getwd()
	parameters := make([]string, 0, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		parameters = append(parameters, syscall.EscapeArg(arg))
	}
	if err := shellExecute("runas", executable, strings.Join(parameters, " "), workingDirectory); err != nil {
		return false, fmt.Errorf("请求 UAC 管理员权限: %w", err)
	}
	return true, nil
}

func windowsProcessElevated() (bool, error) {
	process, _, _ := procGetCurrentProcess.Call()
	var token syscall.Handle
	r1, _, callErr := procOpenProcessToken.Call(process, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return false, callErr
	}
	defer syscall.CloseHandle(token)
	var elevation uint32
	var returned uint32
	r1, _, callErr = procGetTokenInformation.Call(
		uintptr(token), tokenElevationClass, uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)),
	)
	if r1 == 0 {
		return false, callErr
	}
	return elevation != 0, nil
}

func shellExecute(verb, file, parameters, directory string) error {
	verbPtr, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}
	filePtr, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	paramsPtr, err := syscall.UTF16PtrFromString(parameters)
	if err != nil {
		return err
	}
	directoryPtr, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		return err
	}
	result, _, callErr := procShellExecuteW.Call(
		0, uintptr(unsafe.Pointer(verbPtr)), uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(paramsPtr)), uintptr(unsafe.Pointer(directoryPtr)), swShowNormal,
	)
	if result <= 32 {
		return fmt.Errorf("ShellExecuteW 返回 %d: %v", result, callErr)
	}
	return nil
}

func platformOpenBrowser(url string) error {
	return shellExecute("open", url, "", "")
}

func platformDefaultConfigPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, appName, "config.json")
}

func platformDefaultLogPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, appName, "logs", "app.log")
}

func platformFatal(message string) {
	text, _ := syscall.UTF16PtrFromString(message)
	title, _ := syscall.UTF16PtrFromString(appName)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbOK|mbIconError)
}
