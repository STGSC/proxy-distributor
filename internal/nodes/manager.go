package nodes

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/geo"
	"proxy-distributor/internal/models"

	"github.com/sirupsen/logrus"
)

// NodeManager 节点管理器
type NodeManager struct {
	fss         *fss.FSS
	nodes       map[string]*models.Node // 指纹 -> 节点
	tags        map[string][]string     // 标签 -> 节点指纹列表
	mutex       sync.RWMutex
	wal         *fss.WAL
	geoResolver *geo.GeoResolver
}

// NewNodeManager 创建节点管理器
func NewNodeManager(fss *fss.FSS) *NodeManager {
	nm := &NodeManager{
		fss:         fss,
		nodes:       make(map[string]*models.Node),
		tags:        make(map[string][]string),
		wal:         fss.NewWAL(fss.GetPath("nodes/nodes.wal.zst")),
		geoResolver: geo.NewGeoResolver(),
	}

	// 加载现有节点
	if err := nm.loadNodes(); err != nil {
		logrus.Errorf("加载节点失败: %v", err)
	}

	return nm
}

// loadNodes 加载节点数据
func (nm *NodeManager) loadNodes() error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// 加载快照
	snapshotFile := nm.fss.GetPath("nodes/nodes.snapshot.zst")
	if nm.fss.FileExists("nodes/nodes.snapshot.zst") {
		if err := nm.loadSnapshot(snapshotFile); err != nil {
			logrus.Errorf("加载节点快照失败: %v", err)
		}
	}

	// 重放WAL
	if err := nm.replayWAL(); err != nil {
		logrus.Errorf("重放WAL失败: %v", err)
	}

	return nil
}

// loadSnapshot 加载快照
func (nm *NodeManager) loadSnapshot(filename string) error {
	data, err := nm.fss.ReadCompressed(filename)
	if err != nil {
		return err
	}

	var snapshot struct {
		Nodes map[string]*models.Node `json:"nodes"`
		Tags  map[string][]string     `json:"tags"`
	}

	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}

	nm.nodes = snapshot.Nodes
	nm.tags = snapshot.Tags

	return nil
}

// saveSnapshot 保存快照
func (nm *NodeManager) saveSnapshot() error {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	snapshot := struct {
		Nodes map[string]*models.Node `json:"nodes"`
		Tags  map[string][]string     `json:"tags"`
	}{
		Nodes: nm.nodes,
		Tags:  nm.tags,
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	snapshotFile := nm.fss.GetPath("nodes/nodes.snapshot.zst")
	return nm.fss.WriteCompressed(snapshotFile, data)
}

// replayWAL 重放WAL
func (nm *NodeManager) replayWAL() error {
	return nm.wal.Replay(func(record json.RawMessage) error {
		var walRecord models.WALRecord
		if err := json.Unmarshal(record, &walRecord); err != nil {
			return err
		}

		switch walRecord.Op {
		case "upsert":
			var nodeRecord models.NodeUpsertRecord
			if err := json.Unmarshal(record, &nodeRecord); err != nil {
				return err
			}
			nm.upsertNodeInternal(nodeRecord.Node)
		case "delete":
			var nodeRecord models.NodeDeleteRecord
			if err := json.Unmarshal(record, &nodeRecord); err != nil {
				return err
			}
			nm.deleteNodeInternal(nodeRecord.FP)
		}

		return nil
	})
}

// UpsertNode 更新或插入节点
func (nm *NodeManager) UpsertNode(node *models.Node) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// 如果节点没有地理位置信息，尝试从节点名称解析
	if node.GeoCountry == "" && node.GeoCity == "" && node.Name != "" {
		if location, err := nm.geoResolver.ResolveLocation(node.Name); err == nil {
			node.GeoCountry = location.Country
			node.GeoCity = location.City
		} else {
			logrus.Warnf("解析节点地理位置失败: %v", err)
			node.GeoCountry = "Unknown"
			node.GeoCity = "Unknown"
		}
	}

	// 记录WAL
	record := models.NodeUpsertRecord{
		Op:   "upsert",
		FP:   node.Fingerprint,
		Node: node,
	}

	if err := nm.wal.Append(record); err != nil {
		return err
	}

	// 更新内存
	nm.upsertNodeInternal(node)

	return nil
}

// upsertNodeInternal 内部更新节点（不加锁）
func (nm *NodeManager) upsertNodeInternal(node *models.Node) {
	// 删除旧标签
	if oldNode, exists := nm.nodes[node.Fingerprint]; exists {
		for _, tag := range oldNode.Tags {
			nm.removeNodeFromTag(tag, node.Fingerprint)
		}
	}

	// 更新节点
	node.UpdatedAt = time.Now()
	nm.nodes[node.Fingerprint] = node

	// 添加新标签
	for _, tag := range node.Tags {
		nm.addNodeToTag(tag, node.Fingerprint)
	}
}

// DeleteNode 删除节点
func (nm *NodeManager) DeleteNode(fingerprint string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// 记录WAL
	record := models.NodeDeleteRecord{
		Op: "delete",
		FP: fingerprint,
	}

	if err := nm.wal.Append(record); err != nil {
		return err
	}

	// 删除节点
	nm.deleteNodeInternal(fingerprint)

	return nil
}

// deleteNodeInternal 内部删除节点（不加锁）
func (nm *NodeManager) deleteNodeInternal(fingerprint string) {
	if node, exists := nm.nodes[fingerprint]; exists {
		// 从标签中移除
		for _, tag := range node.Tags {
			nm.removeNodeFromTag(tag, fingerprint)
		}

		// 删除节点
		delete(nm.nodes, fingerprint)
	}
}

// GetNode 获取节点
func (nm *NodeManager) GetNode(fingerprint string) (*models.Node, bool) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	node, exists := nm.nodes[fingerprint]
	return node, exists
}

// GetNodes 获取所有节点
func (nm *NodeManager) GetNodes() []*models.Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var nodes []*models.Node
	for _, node := range nm.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// FilterNodes 过滤节点
func (nm *NodeManager) FilterNodes(filter *models.NodeFilter) []*models.Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var result []*models.Node

	for _, node := range nm.nodes {
		// 协议过滤
		if filter.Protocol != "" && node.Protocol != filter.Protocol {
			continue
		}

		// 国家过滤
		if filter.Country != "" && node.GeoCountry != filter.Country {
			continue
		}

		// 查询过滤
		if filter.Query != "" {
			query := strings.ToLower(filter.Query)
			if !strings.Contains(strings.ToLower(node.Name), query) &&
				!strings.Contains(strings.ToLower(node.Host), query) {
				continue
			}
		}

		// 标签过滤
		if len(filter.Tags) > 0 {
			hasTag := false
			for _, filterTag := range filter.Tags {
				for _, nodeTag := range node.Tags {
					if nodeTag == filterTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		result = append(result, node)
	}

	return result
}

// GetNodesByFingerprints 根据指纹列表获取节点
func (nm *NodeManager) GetNodesByFingerprints(fingerprints []string) []*models.Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var nodes []*models.Node
	for _, fp := range fingerprints {
		if node, exists := nm.nodes[fp]; exists {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// GetTags 获取所有标签
func (nm *NodeManager) GetTags() map[string]int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	tags := make(map[string]int)
	for tag, fps := range nm.tags {
		tags[tag] = len(fps)
	}

	return tags
}

// GetCountries 获取所有国家列表
func (nm *NodeManager) GetCountries() map[string]int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	countries := make(map[string]int)
	for _, node := range nm.nodes {
		if node.GeoCountry != "" {
			countries[node.GeoCountry]++
		}
	}

	return countries
}

// GetCities 获取指定国家的城市列表
func (nm *NodeManager) GetCities(country string) map[string]int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	cities := make(map[string]int)
	for _, node := range nm.nodes {
		if node.GeoCountry == country && node.GeoCity != "" {
			cities[node.GeoCity]++
		}
	}

	return cities
}

// GetNodesByTag 根据标签获取节点
func (nm *NodeManager) GetNodesByTag(tag string) []*models.Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	fps, exists := nm.tags[tag]
	if !exists {
		return []*models.Node{}
	}

	var nodes []*models.Node
	for _, fp := range fps {
		if node, exists := nm.nodes[fp]; exists {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// addNodeToTag 添加节点到标签
func (nm *NodeManager) addNodeToTag(tag, fingerprint string) {
	if fps, exists := nm.tags[tag]; exists {
		// 检查是否已存在
		for _, fp := range fps {
			if fp == fingerprint {
				return
			}
		}
		nm.tags[tag] = append(fps, fingerprint)
	} else {
		nm.tags[tag] = []string{fingerprint}
	}
}

// removeNodeFromTag 从标签中移除节点
func (nm *NodeManager) removeNodeFromTag(tag, fingerprint string) {
	if fps, exists := nm.tags[tag]; exists {
		for i, fp := range fps {
			if fp == fingerprint {
				nm.tags[tag] = append(fps[:i], fps[i+1:]...)
				break
			}
		}
		// 如果标签下没有节点了，删除标签
		if len(nm.tags[tag]) == 0 {
			delete(nm.tags, tag)
		}
	}
}

// BatchUpsertNodes 批量更新节点
func (nm *NodeManager) BatchUpsertNodes(nodes []*models.Node) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	for _, node := range nodes {
		// 如果节点没有地理位置信息，尝试从节点名称解析
		if node.GeoCountry == "" && node.GeoCity == "" && node.Name != "" {
			if location, err := nm.geoResolver.ResolveLocation(node.Name); err == nil {
				node.GeoCountry = location.Country
				node.GeoCity = location.City
			} else {
				logrus.Warnf("解析节点地理位置失败: %v", err)
				node.GeoCountry = "Unknown"
				node.GeoCity = "Unknown"
			}
		}

		// 记录WAL
		record := models.NodeUpsertRecord{
			Op:   "upsert",
			FP:   node.Fingerprint,
			Node: node,
		}

		if err := nm.wal.Append(record); err != nil {
			return err
		}

		// 更新内存
		nm.upsertNodeInternal(node)
	}

	return nil
}

// GetStats 获取统计信息
func (nm *NodeManager) GetStats() map[string]interface{} {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_nodes": len(nm.nodes),
		"total_tags":  len(nm.tags),
	}

	// 按协议统计
	protocols := make(map[string]int)
	for _, node := range nm.nodes {
		protocols[node.Protocol]++
	}
	stats["protocols"] = protocols

	// 按国家统计
	countries := make(map[string]int)
	for _, node := range nm.nodes {
		if node.GeoCountry != "" {
			countries[node.GeoCountry]++
		}
	}
	stats["countries"] = countries

	return stats
}

// SaveSnapshot 保存快照
func (nm *NodeManager) SaveSnapshot() error {
	return nm.saveSnapshot()
}

// CleanupExpiredSubscriptionNodes 清理过期的订阅节点
// 这个方法会删除那些在最新订阅中不存在的旧节点
func (nm *NodeManager) CleanupExpiredSubscriptionNodes(providerID string, currentNodeFPs []string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// 获取该订阅源的所有节点
	var expiredNodes []string
	for fp, node := range nm.nodes {
		// 只处理指定订阅源的节点，且不是手动添加的节点
		if node.ProviderID == providerID && node.ProviderID != "manual" {
			// 检查节点是否在当前节点列表中
			found := false
			for _, currentFP := range currentNodeFPs {
				if fp == currentFP {
					found = true
					break
				}
			}

			// 如果节点不在当前列表中，标记为过期
			if !found {
				expiredNodes = append(expiredNodes, fp)
			}
		}
	}

	// 删除过期的节点
	for _, fp := range expiredNodes {
		nm.deleteNodeInternal(fp)
		logrus.Infof("清理过期订阅节点: %s (来源: %s)", fp, providerID)
	}

	if len(expiredNodes) > 0 {
		logrus.Infof("清理了 %d 个过期的订阅节点 (来源: %s)", len(expiredNodes), providerID)
	}

	return nil
}

// GetNodesByProvider 获取指定订阅源的所有节点
func (nm *NodeManager) GetNodesByProvider(providerID string) []*models.Node {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	var nodes []*models.Node
	for _, node := range nm.nodes {
		if node.ProviderID == providerID {
			nodes = append(nodes, node)
		}
	}

	return nodes
}
