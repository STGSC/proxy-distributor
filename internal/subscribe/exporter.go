package subscribe

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-distributor/internal/collections"
	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"
	"proxy-distributor/internal/nodes"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Exporter 订阅导出器
type Exporter struct {
	fss               *fss.FSS
	nodeManager       *nodes.NodeManager
	collectionManager *collections.CollectionManager
	userManager       interface{} // 避免循环导入，使用interface{}
	etagCache         map[string]*models.ETagCache
}

// NewExporter 创建订阅导出器
func NewExporter(fss *fss.FSS, nodeManager *nodes.NodeManager, collectionManager *collections.CollectionManager, userManager interface{}) *Exporter {
	exporter := &Exporter{
		fss:               fss,
		nodeManager:       nodeManager,
		collectionManager: collectionManager,
		userManager:       userManager,
		etagCache:         make(map[string]*models.ETagCache),
	}

	// 加载ETag缓存
	exporter.loadETagCache()

	return exporter
}

// ExportSubscription 导出订阅
func (e *Exporter) ExportSubscription(tokenHash, target string, watermark bool, userID string) ([]byte, string, error) {
	// 获取用户集合
	userCollections := e.getUserCollections(userID)
	var allNodes []*models.Node

	if len(userCollections) > 0 {
		// 如果用户有集合，导出集合中的节点
		for _, collectionID := range userCollections {
			nodeFPs := e.collectionManager.GetCollectionNodes(collectionID)
			nodes := e.nodeManager.GetNodesByFingerprints(nodeFPs)
			allNodes = append(allNodes, nodes...)
		}
	} else {
		// 如果用户没有集合，导出所有可用节点
		allNodes = e.nodeManager.GetNodes()
	}

	// 去重节点
	uniqueNodes := e.deduplicateNodes(allNodes)

	// 根据目标格式导出
	var content []byte
	var err error
	var etag string

	switch target {
	case "clash":
		content, etag, err = e.exportClash(uniqueNodes, watermark, userID)
	case "surge4", "surge5":
		content, etag, err = e.exportSurge(uniqueNodes, watermark, userID, target)
	case "singbox":
		content, etag, err = e.exportSingBox(uniqueNodes, watermark, userID)
	case "v2ray":
		content, etag, err = e.exportV2Ray(uniqueNodes, watermark, userID)
	case "trojan":
		content, etag, err = e.exportTrojan(uniqueNodes, watermark, userID)
	case "ssr":
		content, etag, err = e.exportSSR(uniqueNodes, watermark, userID)
	case "mixed":
		content, etag, err = e.exportMixed(uniqueNodes, watermark, userID)
	case "surfboard":
		content, etag, err = e.exportSurfboard(uniqueNodes, watermark, userID)
	case "quantumult":
		content, etag, err = e.exportQuantumult(uniqueNodes, watermark, userID)
	case "quantumultx":
		content, etag, err = e.exportQuantumultX(uniqueNodes, watermark, userID)
	case "loon":
		content, etag, err = e.exportLoon(uniqueNodes, watermark, userID)
	case "mellow":
		content, etag, err = e.exportMellow(uniqueNodes, watermark, userID)
	case "surge3":
		content, etag, err = e.exportSurge3(uniqueNodes, watermark, userID)
	case "surge2":
		content, etag, err = e.exportSurge2(uniqueNodes, watermark, userID)
	case "clashr":
		content, etag, err = e.exportClashR(uniqueNodes, watermark, userID)
	case "sip002":
		content, etag, err = e.exportSIP002(uniqueNodes, watermark, userID)
	case "sip008":
		content, etag, err = e.exportSIP008(uniqueNodes, watermark, userID)
	case "shadowsocksd":
		content, etag, err = e.exportShadowsocksD(uniqueNodes, watermark, userID)
	case "auto":
		// 自动判断客户端需要从HTTP请求中获取User-Agent
		// 这里需要从调用方传入User-Agent
		content, etag, err = e.exportAuto(uniqueNodes, watermark, userID, "")
	default:
		return nil, "", fmt.Errorf("不支持的导出格式: %s", target)
	}

	if err != nil {
		return nil, "", err
	}

	// 更新ETag缓存
	e.updateETagCache(tokenHash, target, etag, content)

	return content, etag, nil
}

// exportClash 导出Clash格式
func (e *Exporter) exportClash(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	clash := struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}{
		Proxies: []map[string]interface{}{},
	}

	for _, node := range nodes {
		proxy := e.convertNodeToClash(node, watermark, userID)
		clash.Proxies = append(clash.Proxies, proxy)
	}

	// 序列化为YAML
	content, err := yaml.Marshal(clash)
	if err != nil {
		return nil, "", fmt.Errorf("序列化Clash YAML失败: %w", err)
	}

	// 生成ETag
	etag := e.generateETag(content)

	return content, etag, nil
}

// exportV2RayN 导出V2RayN格式
func (e *Exporter) exportV2RayN(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var uris []string

	for _, node := range nodes {
		uri, err := e.convertNodeToURI(node, watermark, userID)
		if err != nil {
			logrus.Warnf("转换节点为URI失败: %s, 错误: %v", node.Name, err)
			continue
		}
		uris = append(uris, uri)
	}

	// 拼接所有URI
	content := strings.Join(uris, "\n")

	// Base64编码
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	// 生成ETag
	etag := e.generateETag([]byte(encoded))

	return []byte(encoded), etag, nil
}

// exportSingBox 导出sing-box格式
func (e *Exporter) exportSingBox(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	singbox := struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}{
		Outbounds: []map[string]interface{}{},
	}

	for _, node := range nodes {
		outbound := e.convertNodeToSingBox(node, watermark, userID)
		singbox.Outbounds = append(singbox.Outbounds, outbound)
	}

	// 序列化为JSON
	content, err := json.MarshalIndent(singbox, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("序列化sing-box JSON失败: %w", err)
	}

	// 生成ETag
	etag := e.generateETag(content)

	return content, etag, nil
}

// exportSIP008 导出SIP008格式
func (e *Exporter) exportSIP008(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	sip008 := struct {
		Version int                      `json:"version"`
		Servers []map[string]interface{} `json:"servers"`
	}{
		Version: 1,
		Servers: []map[string]interface{}{},
	}

	for _, node := range nodes {
		// 只处理Shadowsocks节点
		if node.Protocol == "ss" {
			server := e.convertNodeToSIP008(node, watermark, userID)
			sip008.Servers = append(sip008.Servers, server)
		}
	}

	// 序列化为JSON
	content, err := json.MarshalIndent(sip008, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("序列化SIP008 JSON失败: %w", err)
	}

	// 生成ETag
	etag := e.generateETag(content)

	return content, etag, nil
}

// convertNodeToClash 转换节点为Clash格式
func (e *Exporter) convertNodeToClash(node *models.Node, watermark bool, userID string) map[string]interface{} {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	proxy := map[string]interface{}{
		"name":   name,
		"type":   node.Protocol,
		"server": node.Host,
		"port":   node.Port,
	}

	// 根据协议类型添加特定参数
	switch node.Protocol {
	case "vmess":
		proxy["uuid"] = node.Params["uuid"]
		proxy["alterId"] = 0
		if network, ok := node.Params["network"]; ok {
			proxy["network"] = network
		}
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			proxy["tls"] = true
		}
	case "vless":
		proxy["uuid"] = node.Params["uuid"]
		if network, ok := node.Params["network"]; ok {
			proxy["network"] = network
		}
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			proxy["tls"] = true
		}
	case "ss":
		proxy["cipher"] = node.Params["cipher"]
		proxy["password"] = node.Params["password"]
	case "trojan":
		proxy["password"] = node.Params["password"]
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			proxy["tls"] = true
		}
	}

	return proxy
}

// convertNodeToURI 转换节点为URI
func (e *Exporter) convertNodeToURI(node *models.Node, watermark bool, userID string) (string, error) {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	switch node.Protocol {
	case "vmess":
		return e.convertVMessToURI(node, name)
	case "vless":
		return e.convertVLessToURI(node, name)
	case "ss":
		return e.convertSSToURI(node, name)
	case "trojan":
		return e.convertTrojanToURI(node, name)
	default:
		return "", fmt.Errorf("不支持的协议: %s", node.Protocol)
	}
}

// convertVMessToURI 转换VMess节点为URI
func (e *Exporter) convertVMessToURI(node *models.Node, name string) (string, error) {
	config := map[string]interface{}{
		"v":    "2",
		"ps":   name,
		"add":  node.Host,
		"port": node.Port,
		"id":   node.Params["uuid"],
		"aid":  0,
		"net":  node.Params["network"],
		"type": "none",
	}

	if tls, ok := node.Params["tls"]; ok && tls == "true" {
		config["tls"] = "tls"
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(configJSON)
	return fmt.Sprintf("vmess://%s", encoded), nil
}

// convertVLessToURI 转换VLess节点为URI
func (e *Exporter) convertVLessToURI(node *models.Node, name string) (string, error) {
	// 简化实现，实际需要完整构建VLess URI
	return "", fmt.Errorf("VLess URI转换未实现")
}

// convertSSToURI 转换Shadowsocks节点为URI
func (e *Exporter) convertSSToURI(node *models.Node, name string) (string, error) {
	// 简化实现，实际需要完整构建SS URI
	return "", fmt.Errorf("Shadowsocks URI转换未实现")
}

// convertTrojanToURI 转换Trojan节点为URI
func (e *Exporter) convertTrojanToURI(node *models.Node, name string) (string, error) {
	// 简化实现，实际需要完整构建Trojan URI
	return "", fmt.Errorf("Trojan URI转换未实现")
}

// convertNodeToSingBox 转换节点为sing-box格式
func (e *Exporter) convertNodeToSingBox(node *models.Node, watermark bool, userID string) map[string]interface{} {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	outbound := map[string]interface{}{
		"type":        node.Protocol,
		"tag":         name,
		"server":      node.Host,
		"server_port": node.Port,
	}

	// 根据协议类型添加特定参数
	switch node.Protocol {
	case "vmess":
		outbound["uuid"] = node.Params["uuid"]
		outbound["alter_id"] = 0
		if network, ok := node.Params["network"]; ok {
			outbound["network"] = network
		}
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
			}
		}
	case "vless":
		outbound["uuid"] = node.Params["uuid"]
		if network, ok := node.Params["network"]; ok {
			outbound["network"] = network
		}
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
			}
		}
	case "ss":
		outbound["method"] = node.Params["cipher"]
		outbound["password"] = node.Params["password"]
	case "trojan":
		outbound["password"] = node.Params["password"]
		if tls, ok := node.Params["tls"]; ok && tls == "true" {
			outbound["tls"] = map[string]interface{}{
				"enabled": true,
			}
		}
	}

	return outbound
}

// convertNodeToSIP008 转换节点为SIP008格式
func (e *Exporter) convertNodeToSIP008(node *models.Node, watermark bool, userID string) map[string]interface{} {
	name := node.Name
	if watermark {
		name = e.addWatermark(name, userID)
	}

	server := map[string]interface{}{
		"id":          uuid.New().String(),
		"remarks":     name,
		"server":      node.Host,
		"server_port": node.Port,
		"password":    node.Params["password"],
		"method":      node.Params["cipher"],
	}

	return server
}

// addWatermark 添加水印
func (e *Exporter) addWatermark(name, userID string) string {
	// 生成用户ID的短哈希
	hash := sha256.Sum256([]byte(userID))
	shortID := fmt.Sprintf("%x", hash)[:8]

	return fmt.Sprintf("★%s-%s", shortID, name)
}

// getUserCollections 获取用户集合
func (e *Exporter) getUserCollections(userID string) []string {
	// 通过interface{}调用用户管理器的方法
	if userManager, ok := e.userManager.(interface {
		GetUserCollections(subject string) []string
	}); ok {
		return userManager.GetUserCollections(userID)
	}
	return []string{}
}

// deduplicateNodes 去重节点
func (e *Exporter) deduplicateNodes(nodes []*models.Node) []*models.Node {
	seen := make(map[string]bool)
	var unique []*models.Node

	for _, node := range nodes {
		if !seen[node.Fingerprint] {
			seen[node.Fingerprint] = true
			unique = append(unique, node)
		}
	}

	return unique
}

// generateETag 生成ETag
func (e *Exporter) generateETag(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf("\"%x\"", hash)
}

// loadETagCache 加载ETag缓存
func (e *Exporter) loadETagCache() {
	cacheFile := e.fss.GetPath("state/etag-cache.gob")
	if e.fss.FileExists("state/etag-cache.gob") {
		if err := e.fss.ReadGob(cacheFile, &e.etagCache); err != nil {
			logrus.Errorf("加载ETag缓存失败: %v", err)
		}
	}
}

// saveETagCache 保存ETag缓存
func (e *Exporter) saveETagCache() {
	cacheFile := e.fss.GetPath("state/etag-cache.gob")
	if err := e.fss.EnsureDir("state"); err != nil {
		logrus.Errorf("创建状态目录失败: %v", err)
		return
	}

	if err := e.fss.WriteGob(cacheFile, e.etagCache); err != nil {
		logrus.Errorf("保存ETag缓存失败: %v", err)
	}
}

// updateETagCache 更新ETag缓存
func (e *Exporter) updateETagCache(tokenHash, target, etag string, content []byte) {
	hash := sha256.Sum256(content)
	hashStr := fmt.Sprintf("%x", hash)

	cacheKey := fmt.Sprintf("%s:%s", tokenHash, target)
	e.etagCache[cacheKey] = &models.ETagCache{
		TokenHash: tokenHash,
		Target:    target,
		ETag:      etag,
		Hash:      hashStr,
		Timestamp: time.Now(),
	}

	// 异步保存缓存
	go e.saveETagCache()
}

// GetETag 获取ETag
func (e *Exporter) GetETag(tokenHash, target string) (string, bool) {
	cacheKey := fmt.Sprintf("%s:%s", tokenHash, target)
	if cache, exists := e.etagCache[cacheKey]; exists {
		return cache.ETag, true
	}
	return "", false
}

// 新增的导出函数

// exportSurge 导出Surge格式
func (e *Exporter) exportSurge(nodes []*models.Node, watermark bool, userID string, version string) ([]byte, string, error) {
	var lines []string

	// Surge配置文件头部
	lines = append(lines, "[General]")
	lines = append(lines, "loglevel = notify")
	lines = append(lines, "dns-server = 8.8.8.8, 1.1.1.1")
	lines = append(lines, "")
	lines = append(lines, "[Proxy]")

	// 添加代理节点
	for _, node := range nodes {
		proxy := e.convertNodeToSurge(node, watermark, userID)
		lines = append(lines, proxy)
	}

	lines = append(lines, "")
	lines = append(lines, "[Proxy Group]")
	lines = append(lines, "Proxy = select, auto, fallback, url=http://www.gstatic.com/generate_204, interval=300, timeout=5")
	lines = append(lines, "")
	lines = append(lines, "[Rule]")
	lines = append(lines, "FINAL, Proxy")

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportV2Ray 导出V2Ray格式
func (e *Exporter) exportV2Ray(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	config := map[string]interface{}{
		"outbounds": []map[string]interface{}{},
	}

	for _, node := range nodes {
		outbound := e.convertNodeToV2Ray(node, watermark, userID)
		config["outbounds"] = append(config["outbounds"].([]map[string]interface{}), outbound)
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("序列化V2Ray配置失败: %w", err)
	}

	etag := e.generateETag(content)
	return content, etag, nil
}

// exportTrojan 导出Trojan格式
func (e *Exporter) exportTrojan(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		if node.Protocol == "trojan" {
			line := e.convertNodeToTrojanURI(node, watermark, userID)
			lines = append(lines, line)
		}
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportSSR 导出ShadowsocksR格式
func (e *Exporter) exportSSR(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		if node.Protocol == "ssr" {
			line := e.convertNodeToSSRURI(node, watermark, userID)
			lines = append(lines, line)
		}
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportMixed 导出混合订阅格式
func (e *Exporter) exportMixed(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		uri, err := e.convertNodeToURI(node, watermark, userID)
		if err != nil {
			continue
		}
		lines = append(lines, uri)
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportSurfboard 导出Surfboard格式
func (e *Exporter) exportSurfboard(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	lines = append(lines, "[General]")
	lines = append(lines, "loglevel = notify")
	lines = append(lines, "dns-server = 8.8.8.8, 1.1.1.1")
	lines = append(lines, "")
	lines = append(lines, "[Proxy]")

	for _, node := range nodes {
		proxy := e.convertNodeToSurfboard(node, watermark, userID)
		lines = append(lines, proxy)
	}

	lines = append(lines, "")
	lines = append(lines, "[Proxy Group]")
	lines = append(lines, "Proxy = select, auto, fallback, url=http://www.gstatic.com/generate_204, interval=300, timeout=5")
	lines = append(lines, "")
	lines = append(lines, "[Rule]")
	lines = append(lines, "FINAL, Proxy")

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportQuantumult 导出Quantumult格式
func (e *Exporter) exportQuantumult(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		line := e.convertNodeToQuantumult(node, watermark, userID)
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportQuantumultX 导出Quantumult X格式
func (e *Exporter) exportQuantumultX(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		line := e.convertNodeToQuantumultX(node, watermark, userID)
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportLoon 导出Loon格式
func (e *Exporter) exportLoon(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	lines = append(lines, "[General]")
	lines = append(lines, "loglevel = notify")
	lines = append(lines, "dns-server = 8.8.8.8, 1.1.1.1")
	lines = append(lines, "")
	lines = append(lines, "[Proxy]")

	for _, node := range nodes {
		proxy := e.convertNodeToLoon(node, watermark, userID)
		lines = append(lines, proxy)
	}

	lines = append(lines, "")
	lines = append(lines, "[Proxy Group]")
	lines = append(lines, "Proxy = select, auto, fallback, url=http://www.gstatic.com/generate_204, interval=300, timeout=5")
	lines = append(lines, "")
	lines = append(lines, "[Rule]")
	lines = append(lines, "FINAL, Proxy")

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportMellow 导出Mellow格式
func (e *Exporter) exportMellow(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	config := map[string]interface{}{
		"outbounds": []map[string]interface{}{},
	}

	for _, node := range nodes {
		outbound := e.convertNodeToMellow(node, watermark, userID)
		config["outbounds"] = append(config["outbounds"].([]map[string]interface{}), outbound)
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("序列化Mellow配置失败: %w", err)
	}

	etag := e.generateETag(content)
	return content, etag, nil
}

// exportSurge3 导出Surge 3格式
func (e *Exporter) exportSurge3(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	return e.exportSurge(nodes, watermark, userID, "surge3")
}

// exportSurge2 导出Surge 2格式
func (e *Exporter) exportSurge2(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	return e.exportSurge(nodes, watermark, userID, "surge2")
}

// exportClashR 导出ClashR格式
func (e *Exporter) exportClashR(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	// ClashR使用与Clash相同的格式
	return e.exportClash(nodes, watermark, userID)
}

// exportSIP002 导出SIP002格式
func (e *Exporter) exportSIP002(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		if node.Protocol == "ss" {
			line := e.convertNodeToSIP002(node, watermark, userID)
			lines = append(lines, line)
		}
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportShadowsocksD 导出ShadowsocksD格式
func (e *Exporter) exportShadowsocksD(nodes []*models.Node, watermark bool, userID string) ([]byte, string, error) {
	var lines []string

	for _, node := range nodes {
		if node.Protocol == "ss" {
			line := e.convertNodeToShadowsocksD(node, watermark, userID)
			lines = append(lines, line)
		}
	}

	content := strings.Join(lines, "\n")
	etag := e.generateETag([]byte(content))

	return []byte(content), etag, nil
}

// exportAuto 自动判断客户端格式
func (e *Exporter) exportAuto(nodes []*models.Node, watermark bool, userID string, userAgent string) ([]byte, string, error) {
	// 根据User-Agent判断客户端类型
	clientType := e.detectClientType(userAgent)

	switch clientType {
	case "clash":
		return e.exportClash(nodes, watermark, userID)
	case "surge":
		return e.exportSurge(nodes, watermark, userID, "surge4")
	case "quantumultx":
		return e.exportQuantumultX(nodes, watermark, userID)
	case "loon":
		return e.exportLoon(nodes, watermark, userID)
	default:
		// 默认返回混合格式
		return e.exportMixed(nodes, watermark, userID)
	}
}

// detectClientType 检测客户端类型
func (e *Exporter) detectClientType(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "clash") {
		return "clash"
	} else if strings.Contains(ua, "surge") {
		return "surge"
	} else if strings.Contains(ua, "quantumult") {
		return "quantumultx"
	} else if strings.Contains(ua, "loon") {
		return "loon"
	} else if strings.Contains(ua, "v2ray") {
		return "v2ray"
	} else if strings.Contains(ua, "shadowsocks") {
		return "ss"
	}

	return "mixed"
}

// ExportSubscriptionWithUA 导出订阅（带User-Agent）
func (e *Exporter) ExportSubscriptionWithUA(tokenHash, target string, watermark bool, userID string, userAgent string) ([]byte, string, error) {
	// 获取用户集合
	userCollections := e.getUserCollections(userID)
	var allNodes []*models.Node

	if len(userCollections) > 0 {
		// 如果用户有集合，导出集合中的节点
		for _, collectionID := range userCollections {
			nodeFPs := e.collectionManager.GetCollectionNodes(collectionID)
			nodes := e.nodeManager.GetNodesByFingerprints(nodeFPs)
			allNodes = append(allNodes, nodes...)
		}
	} else {
		// 如果用户没有集合，导出所有可用节点
		allNodes = e.nodeManager.GetNodes()
	}

	// 去重节点
	uniqueNodes := e.deduplicateNodes(allNodes)

	// 根据目标格式导出
	var content []byte
	var err error
	var etag string

	switch target {
	case "auto":
		content, etag, err = e.exportAuto(uniqueNodes, watermark, userID, userAgent)
	default:
		return nil, "", fmt.Errorf("不支持的导出格式: %s", target)
	}

	if err != nil {
		return nil, "", err
	}

	// 更新ETag缓存
	e.updateETagCache(tokenHash, target, etag, content)

	return content, etag, nil
}
