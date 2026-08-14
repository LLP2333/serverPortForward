//go:build !windows

package app

import (
	"fmt"
	"os"
	"path/filepath"
)

func platformSupported() bool { return false }

func platformEnsureElevated() (bool, error) {
	return false, fmt.Errorf("仅支持 Windows 10/11")
}

func platformOpenBrowser(string) error {
	return fmt.Errorf("仅支持 Windows 10/11")
}

func platformDefaultConfigPath() string {
	return filepath.Join(os.TempDir(), appName, "config.json")
}

func platformDefaultLogPath() string {
	return filepath.Join(os.TempDir(), appName, "app.log")
}

func platformFatal(message string) {
	fmt.Fprintln(os.Stderr, message)
}
