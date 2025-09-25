package logger

import (
	"proxy-distributor/internal/config"

	"github.com/sirupsen/logrus"
)

// Init 初始化日志系统
func Init(cfg config.LogConfig) {
	// 设置日志级别
	switch cfg.Level {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

	// 设置日志格式
	switch cfg.Format {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{})
	default:
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
}
