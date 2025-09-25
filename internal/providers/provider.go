package providers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ProviderManager 订阅源管理器
type ProviderManager struct {
	fss         *fss.FSS
	providers   map[string]*models.Provider
	cron        *cron.Cron
	client      *http.Client
	nodeManager interface{} // 节点管理器接口，避免循环依赖
}

// NewProviderManager 创建订阅源管理器
func NewProviderManager(fss *fss.FSS) *ProviderManager {
	return &ProviderManager{
		fss:         fss,
		providers:   make(map[string]*models.Provider),
		cron:        cron.New(),
		nodeManager: nil, // 稍后设置
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetNodeManager 设置节点管理器
func (pm *ProviderManager) SetNodeManager(nodeManager interface{}) {
	pm.nodeManager = nodeManager
}

// LoadProviders 加载订阅源配置
func (pm *ProviderManager) LoadProviders() error {
	providersFile := pm.fss.GetPath("providers.yml")

	// 如果文件不存在，创建默认配置
	if !pm.fss.FileExists("providers.yml") {
		defaultProviders := []*models.Provider{}
		if err := pm.fss.WriteJSON(providersFile, defaultProviders); err != nil {
			return fmt.Errorf("创建默认订阅源配置失败: %w", err)
		}
	}

	// 读取订阅源配置
	var providers []*models.Provider
	if err := pm.fss.ReadJSON(providersFile, &providers); err != nil {
		return fmt.Errorf("读取订阅源配置失败: %w", err)
	}

	// 加载到内存
	pm.providers = make(map[string]*models.Provider)
	for _, provider := range providers {
		pm.providers[provider.ID] = provider
	}

	// 启动定时任务
	pm.startCronJobs()

	return nil
}

// SaveProviders 保存订阅源配置
func (pm *ProviderManager) SaveProviders() error {
	providersFile := pm.fss.GetPath("providers.yml")

	var providers []*models.Provider
	for _, provider := range pm.providers {
		providers = append(providers, provider)
	}

	return pm.fss.WriteJSON(providersFile, providers)
}

// GetProviders 获取所有订阅源
func (pm *ProviderManager) GetProviders() []*models.Provider {
	var providers []*models.Provider
	for _, provider := range pm.providers {
		providers = append(providers, provider)
	}
	return providers
}

// GetProvider 获取指定订阅源
func (pm *ProviderManager) GetProvider(id string) (*models.Provider, bool) {
	provider, exists := pm.providers[id]
	return provider, exists
}

// AddProvider 添加订阅源
func (pm *ProviderManager) AddProvider(provider *models.Provider) error {
	if provider.ID == "" {
		provider.ID = generateProviderID()
	}

	provider.Status = "active"
	pm.providers[provider.ID] = provider

	// 保存配置
	if err := pm.SaveProviders(); err != nil {
		return err
	}

	// 启动定时任务
	pm.scheduleProvider(provider)

	// 立即抓取一次
	go pm.FetchProvider(provider.ID)

	return nil
}

// UpdateProvider 更新订阅源
func (pm *ProviderManager) UpdateProvider(id string, provider *models.Provider) error {
	if _, exists := pm.providers[id]; !exists {
		return fmt.Errorf("订阅源不存在: %s", id)
	}

	provider.ID = id
	pm.providers[id] = provider

	// 保存配置
	if err := pm.SaveProviders(); err != nil {
		return err
	}

	// 重新调度定时任务
	pm.scheduleProvider(provider)

	return nil
}

// DeleteProvider 删除订阅源
func (pm *ProviderManager) DeleteProvider(id string) error {
	if _, exists := pm.providers[id]; !exists {
		return fmt.Errorf("订阅源不存在: %s", id)
	}

	delete(pm.providers, id)

	// 保存配置
	if err := pm.SaveProviders(); err != nil {
		return err
	}

	return nil
}

// FetchProvider 抓取指定订阅源
func (pm *ProviderManager) FetchProvider(id string) error {
	provider, exists := pm.providers[id]
	if !exists {
		return fmt.Errorf("订阅源不存在: %s", id)
	}

	logrus.Infof("开始抓取订阅源: %s (%s)", provider.Name, provider.URL)

	// 更新抓取时间
	provider.LastFetch = time.Now()

	// 抓取订阅内容
	content, err := pm.fetchSubscription(provider)
	if err != nil {
		provider.Status = "error"
		provider.ErrorMsg = err.Error()
		logrus.Errorf("抓取订阅源失败: %s, 错误: %v", provider.Name, err)
		return err
	}

	// 保存原始订阅快照
	if err := pm.saveSubscriptionSnapshot(provider, content); err != nil {
		provider.Status = "error"
		provider.ErrorMsg = fmt.Sprintf("保存订阅快照失败: %v", err)
		logrus.Errorf("保存订阅快照失败: %s, 错误: %v", provider.Name, err)
		// 保存状态到文件
		pm.SaveProviders()
		return err
	}

	// 解析节点
	nodes, err := pm.parseSubscription(content, provider)
	if err != nil {
		provider.Status = "error"
		provider.ErrorMsg = err.Error()
		logrus.Errorf("解析订阅内容失败: %s, 错误: %v", provider.Name, err)
		// 保存状态到文件
		pm.SaveProviders()
		return err
	}

	// 保存节点到节点管理器
	if pm.nodeManager != nil && len(nodes) > 0 {
		// 使用反射调用BatchUpsertNodes方法
		if batchUpsertNodes, ok := pm.nodeManager.(interface {
			BatchUpsertNodes(nodes []*models.Node) error
		}); ok {
			if err := batchUpsertNodes.BatchUpsertNodes(nodes); err != nil {
				provider.Status = "error"
				provider.ErrorMsg = fmt.Sprintf("保存节点到节点管理器失败: %v", err)
				logrus.Errorf("保存节点到节点管理器失败: %s, 错误: %v", provider.Name, err)
				// 保存状态到文件
				pm.SaveProviders()
				return err
			} else {
				logrus.Infof("成功保存 %d 个节点到节点管理器", len(nodes))
			}
		}

		// 清理过期的订阅节点
		if cleanupExpiredNodes, ok := pm.nodeManager.(interface {
			CleanupExpiredSubscriptionNodes(providerID string, currentNodeFPs []string) error
		}); ok {
			// 提取当前节点的指纹列表
			var currentNodeFPs []string
			for _, node := range nodes {
				currentNodeFPs = append(currentNodeFPs, node.Fingerprint)
			}

			// 清理过期的节点
			if err := cleanupExpiredNodes.CleanupExpiredSubscriptionNodes(provider.ID, currentNodeFPs); err != nil {
				logrus.Errorf("清理过期订阅节点失败: %s, 错误: %v", provider.Name, err)
				// 不返回错误，因为主要功能已经完成
			}
		}
	}

	// 更新状态
	provider.Status = "active"
	provider.LastSuccess = time.Now()
	provider.ErrorMsg = ""

	// 保存状态到文件
	if err := pm.SaveProviders(); err != nil {
		logrus.Errorf("保存订阅源状态失败: %s, 错误: %v", provider.Name, err)
	}

	logrus.Infof("抓取订阅源成功: %s, 解析到 %d 个节点", provider.Name, len(nodes))

	return nil
}

// fetchSubscription 抓取订阅内容
func (pm *ProviderManager) fetchSubscription(provider *models.Provider) ([]byte, error) {
	req, err := http.NewRequest("GET", provider.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置认证头
	if provider.AuthHeader != "" {
		parts := strings.SplitN(provider.AuthHeader, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// 设置User-Agent
	req.Header.Set("User-Agent", "ProxyDistributor/1.0")

	// 创建HTTP客户端
	client := pm.client
	if provider.Proxy != "" {
		proxyURL, err := url.Parse(provider.Proxy)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %w", err)
		}
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	return content, nil
}

// saveSubscriptionSnapshot 保存订阅快照
func (pm *ProviderManager) saveSubscriptionSnapshot(provider *models.Provider, content []byte) error {
	// 计算内容哈希
	hash := sha256.Sum256(content)
	hashStr := fmt.Sprintf("%x", hash)

	// 创建快照文件名
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	filename := fmt.Sprintf("%s.br", timestamp)

	// 确保目录存在
	if err := pm.fss.EnsureDir(fmt.Sprintf("subs/%s", provider.ID)); err != nil {
		return err
	}

	// 压缩并保存内容
	contentPath := pm.fss.GetPath(fmt.Sprintf("subs/%s/%s", provider.ID, filename))
	if err := pm.fss.WriteCompressed(contentPath, content); err != nil {
		return err
	}

	// 更新索引
	indexFile := pm.fss.GetPath(fmt.Sprintf("subs/%s/index.json", provider.ID))
	var index []map[string]interface{}
	if pm.fss.FileExists(fmt.Sprintf("subs/%s/index.json", provider.ID)) {
		pm.fss.ReadJSON(indexFile, &index)
	}

	// 添加新记录
	record := map[string]interface{}{
		"filename":  filename,
		"hash":      hashStr,
		"size":      len(content),
		"timestamp": timestamp,
	}
	index = append(index, record)

	// 保存索引
	return pm.fss.WriteJSON(indexFile, index)
}

// parseSubscription 解析订阅内容
func (pm *ProviderManager) parseSubscription(content []byte, provider *models.Provider) ([]*models.Node, error) {
	// 尝试不同的解析方式

	// 1. 尝试解析为Clash YAML
	if nodes, err := pm.parseClashYAML(content, provider); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	// 2. 尝试解析为Base64编码的URI列表
	if nodes, err := pm.parseBase64URIs(content, provider); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	// 3. 尝试解析为JSON格式
	if nodes, err := pm.parseJSON(content, provider); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	return nil, fmt.Errorf("无法解析订阅内容")
}

// parseClashYAML 解析Clash YAML格式
func (pm *ProviderManager) parseClashYAML(content []byte, provider *models.Provider) ([]*models.Node, error) {
	var clash struct {
		Proxies []struct {
			Name     string                 `yaml:"name"`
			Type     string                 `yaml:"type"`
			Server   string                 `yaml:"server"`
			Port     int                    `yaml:"port"`
			UUID     string                 `yaml:"uuid,omitempty"`
			Password string                 `yaml:"password,omitempty"`
			Cipher   string                 `yaml:"cipher,omitempty"`
			Network  string                 `yaml:"network,omitempty"`
			WS       map[string]interface{} `yaml:"ws,omitempty"`
			TLS      bool                   `yaml:"tls,omitempty"`
		} `yaml:"proxies"`
	}

	if err := yaml.Unmarshal(content, &clash); err != nil {
		return nil, err
	}

	var nodes []*models.Node
	for _, proxy := range clash.Proxies {
		node := &models.Node{
			Protocol:   proxy.Type,
			Host:       proxy.Server,
			Port:       proxy.Port,
			Name:       proxy.Name,
			Params:     make(map[string]string),
			ProviderID: provider.ID,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		// 根据协议类型设置参数
		switch proxy.Type {
		case "vmess":
			node.Params["uuid"] = proxy.UUID
			node.Params["network"] = proxy.Network
			if proxy.TLS {
				node.Params["tls"] = "true"
			}
		case "vless":
			node.Params["uuid"] = proxy.UUID
			node.Params["network"] = proxy.Network
			if proxy.TLS {
				node.Params["tls"] = "true"
			}
		case "ss":
			node.Params["password"] = proxy.Password
			node.Params["cipher"] = proxy.Cipher
		case "trojan":
			node.Params["password"] = proxy.Password
			if proxy.TLS {
				node.Params["tls"] = "true"
			}
		}

		// 生成指纹
		node.Fingerprint = pm.generateFingerprint(node)

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// parseBase64URIs 解析Base64编码的URI列表
func (pm *ProviderManager) parseBase64URIs(content []byte, provider *models.Provider) ([]*models.Node, error) {
	contentStr := string(content)

	// 首先尝试标准Base64解码
	decoded, err := base64.StdEncoding.DecodeString(contentStr)
	if err != nil {
		// 如果标准Base64解码失败，尝试处理连续Base64字符串
		logrus.Debugf("标准Base64解码失败，尝试连续Base64解析: %v", err)
		return pm.parseContinuousBase64(contentStr, provider)
	}

	// 按行分割
	lines := strings.Split(string(decoded), "\n")
	var nodes []*models.Node

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		node, err := pm.parseURI(line, provider)
		if err != nil {
			logrus.Warnf("解析URI失败: %s, 错误: %v", line, err)
			continue
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// parseContinuousBase64 解析连续的Base64字符串
func (pm *ProviderManager) parseContinuousBase64(contentStr string, provider *models.Provider) ([]*models.Node, error) {
	var nodes []*models.Node

	logrus.Debugf("开始解析连续Base64字符串，长度: %d", len(contentStr))

	// 查找trojan://的Base64编码
	trojanPrefix := base64.StdEncoding.EncodeToString([]byte("trojan://"))
	logrus.Debugf("trojan://的Base64编码: %s", trojanPrefix)

	// 如果内容以trojan://的Base64编码开头
	if strings.HasPrefix(contentStr, trojanPrefix) {
		logrus.Debugf("内容以trojan://的Base64编码开头")

		// 尝试不同的Base64长度来找到完整的URI
		for length := 200; length <= len(contentStr) && length <= 3000; length += 50 {
			part := contentStr[:length]
			decoded, err := base64.StdEncoding.DecodeString(part)
			if err != nil {
				continue
			}

			decodedStr := string(decoded)
			logrus.Debugf("Base64解码成功，长度: %d", length)

			// 检查是否包含trojan URI
			if strings.Contains(decodedStr, "trojan://") {
				logrus.Debugf("找到trojan URI，开始提取")

				// 按行分割并提取trojan URI
				lines := strings.Split(decodedStr, "\n")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "trojan://") {
						logrus.Debugf("找到trojan URI第%d个: %s", i+1, line[:min(100, len(line))])

						node, err := pm.parseURI(line, provider)
						if err != nil {
							logrus.Warnf("解析URI失败: %s, 错误: %v", line, err)
							continue
						}
						nodes = append(nodes, node)
					}
				}

				// 如果找到了节点，就停止
				if len(nodes) > 0 {
					logrus.Debugf("成功解析到 %d 个节点", len(nodes))
					break
				}
			}
		}
	} else {
		logrus.Debugf("内容不以trojan://的Base64编码开头，实际开头: %s", contentStr[:min(50, len(contentStr))])
	}

	return nodes, nil
}

// parseJSON 解析JSON格式
func (pm *ProviderManager) parseJSON(content []byte, provider *models.Provider) ([]*models.Node, error) {
	var data interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, err
	}

	// 这里可以根据具体的JSON格式进行解析
	// 暂时返回空，需要根据实际格式实现
	return nil, fmt.Errorf("JSON格式解析未实现")
}

// parseURI 解析单个URI
func (pm *ProviderManager) parseURI(uri string, provider *models.Provider) (*models.Node, error) {
	if strings.HasPrefix(uri, "vmess://") {
		return pm.parseVMessURI(uri, provider)
	} else if strings.HasPrefix(uri, "vless://") {
		return pm.parseVLessURI(uri, provider)
	} else if strings.HasPrefix(uri, "ss://") {
		return pm.parseSSURI(uri, provider)
	} else if strings.HasPrefix(uri, "trojan://") {
		return pm.parseTrojanURI(uri, provider)
	}

	return nil, fmt.Errorf("不支持的URI协议: %s", uri)
}

// parseVMessURI 解析VMess URI
func (pm *ProviderManager) parseVMessURI(uri string, provider *models.Provider) (*models.Node, error) {
	// 移除协议前缀
	encoded := strings.TrimPrefix(uri, "vmess://")

	// Base64解码
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %w", err)
	}

	// 解析JSON
	var config struct {
		V    string      `json:"v"`
		PS   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"` // 端口可能是字符串或数字
		ID   string      `json:"id"`
		Aid  interface{} `json:"aid"` // aid也可能是字符串或数字
		Net  string      `json:"net"`
		Type string      `json:"type"`
		TLS  string      `json:"tls"`
	}

	if err := json.Unmarshal(decoded, &config); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}

	// 处理端口号（可能是字符串或数字）
	var port int
	switch v := config.Port.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	case string:
		if _, err := fmt.Sscanf(v, "%d", &port); err != nil {
			return nil, fmt.Errorf("无效的端口号: %s", v)
		}
	default:
		return nil, fmt.Errorf("无效的端口号类型: %T", config.Port)
	}

	// 处理aid（可能是字符串或数字）
	var aidStr string
	switch v := config.Aid.(type) {
	case float64:
		aidStr = fmt.Sprintf("%.0f", v)
	case int:
		aidStr = fmt.Sprintf("%d", v)
	case string:
		aidStr = v
	default:
		aidStr = "0"
	}

	node := &models.Node{
		Protocol:   "vmess",
		Host:       config.Add,
		Port:       port,
		Name:       config.PS,
		ProviderID: provider.ID,
		Params: map[string]string{
			"uuid":    config.ID,
			"aid":     aidStr,
			"network": config.Net,
			"type":    config.Type,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if config.TLS == "tls" {
		node.Params["tls"] = "true"
	}

	// 生成指纹
	node.Fingerprint = pm.generateFingerprint(node)

	return node, nil
}

// parseVLessURI 解析VLess URI
func (pm *ProviderManager) parseVLessURI(uri string, provider *models.Provider) (*models.Node, error) {
	// 简化实现，实际需要完整解析
	return nil, fmt.Errorf("VLess URI解析未实现")
}

// parseSSURI 解析Shadowsocks URI
func (pm *ProviderManager) parseSSURI(uri string, provider *models.Provider) (*models.Node, error) {
	// 简化实现，实际需要完整解析
	return nil, fmt.Errorf("Shadowsocks URI解析未实现")
}

// parseTrojanURI 解析Trojan URI
func (pm *ProviderManager) parseTrojanURI(uri string, provider *models.Provider) (*models.Node, error) {
	// 简化实现，实际需要完整解析
	return nil, fmt.Errorf("Trojan URI解析未实现")
}

// generateFingerprint 生成节点指纹
func (pm *ProviderManager) generateFingerprint(node *models.Node) string {
	data := fmt.Sprintf("%s:%s:%d:%s", node.Protocol, node.Host, node.Port, node.Name)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// startCronJobs 启动定时任务
func (pm *ProviderManager) startCronJobs() {
	pm.cron.Start()

	for _, provider := range pm.providers {
		pm.scheduleProvider(provider)
	}
}

// scheduleProvider 调度订阅源抓取任务
func (pm *ProviderManager) scheduleProvider(provider *models.Provider) {
	if provider.FetchCron == "" {
		return
	}

	// 移除现有任务（如果有）
	// 这里简化实现，实际应该跟踪任务ID

	// 添加新任务
	pm.cron.AddFunc(provider.FetchCron, func() {
		if err := pm.FetchProvider(provider.ID); err != nil {
			logrus.Errorf("定时抓取订阅源失败: %s, 错误: %v", provider.Name, err)
		}
	})
}

// DisableProvider 禁用订阅源
func (pm *ProviderManager) DisableProvider(id string) error {
	provider, exists := pm.providers[id]
	if !exists {
		return fmt.Errorf("订阅源不存在: %s", id)
	}

	provider.Status = "disabled"

	// 保存配置
	if err := pm.SaveProviders(); err != nil {
		return err
	}

	logrus.Infof("禁用订阅源: %s", provider.Name)
	return nil
}

// EnableProvider 启用订阅源
func (pm *ProviderManager) EnableProvider(id string) error {
	provider, exists := pm.providers[id]
	if !exists {
		return fmt.Errorf("订阅源不存在: %s", id)
	}

	provider.Status = "active"
	provider.ErrorMsg = "" // 清除错误信息

	// 保存配置
	if err := pm.SaveProviders(); err != nil {
		return err
	}

	// 重新调度定时任务
	pm.scheduleProvider(provider)

	// 立即抓取一次
	go pm.FetchProvider(provider.ID)

	logrus.Infof("启用订阅源: %s", provider.Name)
	return nil
}

// generateProviderID 生成订阅源ID
func generateProviderID() string {
	return fmt.Sprintf("provider_%d", time.Now().Unix())
}
