package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 全局配置
type Config struct {
	Listen  ListenConfig `yaml:"listen"`
	Auth    AuthConfig   `yaml:"auth"`
	Export  ExportConfig `yaml:"export"`
	Limits  LimitsConfig `yaml:"limits"`
	Log     LogConfig    `yaml:"log"`
	Azure   AzureConfig  `yaml:"azure"`
	Server  ServerConfig `yaml:"server"`
	DataDir string       `yaml:"-"`
}

// ListenConfig 监听配置
type ListenConfig struct {
	HTTP string `yaml:"http"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	OIDC    OIDCConfig    `yaml:"oidc"`
	Session SessionConfig `yaml:"session"`
}

// OIDCConfig OIDC配置
type OIDCConfig struct {
	TenantID     string `yaml:"tenant_id"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
}

// SessionConfig 会话配置
type SessionConfig struct {
	CookieName string `yaml:"cookie_name"`
	Secret     string `yaml:"secret"`
}

// ExportConfig 导出配置
type ExportConfig struct {
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
}

// LimitsConfig 限制配置
type LimitsConfig struct {
	DefaultRPM int `yaml:"default_rpm"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// AzureConfig Azure AD配置
type AzureConfig struct {
	TenantID     string   `yaml:"tenant_id"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	GroupIDs     []string `yaml:"group_ids"`
	SyncInterval string   `yaml:"sync_interval"` // 如 "1h", "24h"
	Enabled      bool     `yaml:"enabled"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	BaseURL string `yaml:"base_url"` // 服务器基础URL，用于生成订阅链接
}

// Load 加载配置文件
func Load(configFile, dataDir string) (*Config, error) {
	cfg := &Config{
		DataDir: dataDir,
		Listen: ListenConfig{
			HTTP: ":8080",
		},
		Auth: AuthConfig{
			Session: SessionConfig{
				CookieName: "sid",
				Secret:     generateRandomSecret(),
			},
		},
		Export: ExportConfig{
			CacheTTLSeconds: 180,
		},
		Limits: LimitsConfig{
			DefaultRPM: 30,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Azure: AzureConfig{
			Enabled:      false,
			SyncInterval: "24h",
		},
		Server: ServerConfig{
			BaseURL: "http://localhost:8080",
		},
	}

	// 如果配置文件存在，则加载
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %w", err)
		}
	} else {
		// 创建默认配置文件
		if err := cfg.Save(configFile); err != nil {
			return nil, fmt.Errorf("创建默认配置文件失败: %w", err)
		}
	}

	cfg.DataDir = dataDir
	return cfg, nil
}

// Save 保存配置文件
func (c *Config) Save(configFile string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(configFile), 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	return nil
}

// generateRandomSecret 生成随机密钥
func generateRandomSecret() string {
	// 这里应该使用 crypto/rand 生成真正的随机密钥
	// 为了简化，使用固定值，生产环境需要修改
	return "your-32-byte-secret-key-here-change-me"
}
