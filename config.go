package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ConfigRepository interface {
	Load() (Config, error)
	Save(Config) error
}

type FileConfigRepository struct {
	Path string
}

func (r FileConfigRepository) Load() (Config, error) {
	f, err := os.Open(r.Path)
	if errors.Is(err, os.ErrNotExist) {
		return newConfig(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("打开配置: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(io.LimitReader(f, 2<<20))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("解析配置: %w", err)
	}
	if cfg.Version != configVersion {
		return Config{}, fmt.Errorf("不支持的配置版本 %d", cfg.Version)
	}
	if cfg.ManagedRules == nil {
		cfg.ManagedRules = []ManagedRule{}
	}
	return cfg, nil
}

func (r FileConfigRepository) Save(cfg Config) error {
	cfg.Version = configVersion
	if cfg.ManagedRules == nil {
		cfg.ManagedRules = []ManagedRule{}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(r.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时配置: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("设置配置权限: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入配置: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("同步配置: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭配置: %w", err)
	}
	if err := os.Rename(tmpName, r.Path); err != nil {
		return fmt.Errorf("替换配置: %w", err)
	}
	return nil
}
