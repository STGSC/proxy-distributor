package main

import (
	"flag"
	"os"
	"path/filepath"

	"proxy-distributor/internal/api"
	"proxy-distributor/internal/config"
	"proxy-distributor/internal/logger"

	"github.com/sirupsen/logrus"
)

func main() {
	var (
		dataDir    = flag.String("data", "./data", "数据目录路径")
		configFile = flag.String("config", "", "配置文件路径（默认: data/config.yml）")
		port       = flag.String("port", "", "监听端口（覆盖配置文件）")
		debug      = flag.Bool("debug", false, "启用调试模式")
	)
	flag.Parse()

	// 设置日志级别
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// 确保数据目录存在
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		logrus.Fatalf("创建数据目录失败: %v", err)
	}

	// 设置配置文件路径
	if *configFile == "" {
		*configFile = filepath.Join(*dataDir, "config.yml")
	}

	// 加载配置
	cfg, err := config.Load(*configFile, *dataDir)
	if err != nil {
		logrus.Fatalf("加载配置失败: %v", err)
	}

	// 覆盖端口配置
	if *port != "" {
		cfg.Listen.HTTP = ":" + *port
	}

	// 初始化日志
	logger.Init(cfg.Log)

	// 启动服务器
	server := api.NewServer(cfg)
	if err := server.Start(); err != nil {
		logrus.Fatalf("启动服务器失败: %v", err)
	}
}
