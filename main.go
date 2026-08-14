package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	if !platformSupported() {
		platformFatal("ServerPortForward 只能在 Windows 10/11 上运行。\n可以在 macOS 上交叉编译 Windows EXE，但不能直接运行。")
		return
	}
	relaunched, err := platformEnsureElevated()
	if err != nil {
		platformFatal("无法获得管理员权限：\n" + err.Error())
		return
	}
	if relaunched {
		return
	}

	logFile, err := setupLogFile(platformDefaultLogPath())
	if err == nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	manager := NewManager(
		OSCommandRunner{},
		FileConfigRepository{Path: platformDefaultConfigPath()},
	)
	server, err := NewAppServer(manager)
	if err != nil {
		platformFatal("初始化本地管理服务失败：\n" + err.Error())
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("管理服务退出: %v", err)
		platformFatal("本地管理服务异常退出：\n" + err.Error())
	}
}

func setupLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil && info.Size() > 1<<20 {
		_ = os.Remove(path + ".old")
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开日志: %w", err)
	}
	return f, nil
}
