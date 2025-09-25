package collections

import (
	"fmt"
	"strings"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// CollectionManager 集合管理器
type CollectionManager struct {
	fss         *fss.FSS
	collections map[string]*models.Collection
}

// NewCollectionManager 创建集合管理器
func NewCollectionManager(fss *fss.FSS) *CollectionManager {
	cm := &CollectionManager{
		fss:         fss,
		collections: make(map[string]*models.Collection),
	}

	// 加载现有集合
	if err := cm.loadCollections(); err != nil {
		logrus.Errorf("加载集合失败: %v", err)
	}

	return cm
}

// loadCollections 加载集合数据
func (cm *CollectionManager) loadCollections() error {
	// 确保目录存在
	if err := cm.fss.EnsureDir("collections"); err != nil {
		return err
	}

	// 列出所有集合文件
	files, err := cm.fss.ListFiles("collections")
	if err != nil {
		return err
	}

	// 加载每个集合文件
	for _, file := range files {
		if !strings.HasSuffix(file, ".yml") {
			continue
		}

		collectionID := strings.TrimSuffix(file, ".yml")

		var collection models.Collection
		collectionFile := cm.fss.GetPath(fmt.Sprintf("collections/%s", file))
		if err := cm.fss.ReadJSON(collectionFile, &collection); err != nil {
			logrus.Errorf("读取集合文件失败: %s, 错误: %v", file, err)
			continue
		}

		collection.ID = collectionID
		cm.collections[collectionID] = &collection
	}

	return nil
}

// GetCollections 获取所有集合
func (cm *CollectionManager) GetCollections() []*models.Collection {
	var collections []*models.Collection
	for _, collection := range cm.collections {
		collections = append(collections, collection)
	}
	return collections
}

// GetCollection 获取指定集合
func (cm *CollectionManager) GetCollection(id string) (*models.Collection, bool) {
	collection, exists := cm.collections[id]
	return collection, exists
}

// CreateCollection 创建集合
func (cm *CollectionManager) CreateCollection(name string, tags []string) (*models.Collection, error) {
	collection := &models.Collection{
		ID:        uuid.New().String(),
		Name:      name,
		NodeFPs:   []string{},
		Sort:      []string{},
		Tags:      tags,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 保存到文件
	if err := cm.saveCollection(collection); err != nil {
		return nil, err
	}

	// 添加到内存
	cm.collections[collection.ID] = collection

	return collection, nil
}

// UpdateCollection 更新集合
func (cm *CollectionManager) UpdateCollection(id string, name string, tags []string) error {
	collection, exists := cm.collections[id]
	if !exists {
		return fmt.Errorf("集合不存在: %s", id)
	}

	collection.Name = name
	collection.Tags = tags
	collection.UpdatedAt = time.Now()

	// 保存到文件
	return cm.saveCollection(collection)
}

// DeleteCollection 删除集合
func (cm *CollectionManager) DeleteCollection(id string) error {
	_, exists := cm.collections[id]
	if !exists {
		return fmt.Errorf("集合不存在: %s", id)
	}

	// 删除文件
	if err := cm.fss.RemoveFile(fmt.Sprintf("collections/%s.yml", id)); err != nil {
		return err
	}

	// 从内存中删除
	delete(cm.collections, id)

	return nil
}

// AddNodesToCollection 添加节点到集合
func (cm *CollectionManager) AddNodesToCollection(collectionID string, nodeFPs []string) error {
	collection, exists := cm.collections[collectionID]
	if !exists {
		return fmt.Errorf("集合不存在: %s", collectionID)
	}

	// 去重并添加新节点
	existingFPs := make(map[string]bool)
	for _, fp := range collection.NodeFPs {
		existingFPs[fp] = true
	}

	for _, fp := range nodeFPs {
		if !existingFPs[fp] {
			collection.NodeFPs = append(collection.NodeFPs, fp)
			collection.Sort = append(collection.Sort, fp)
		}
	}

	collection.UpdatedAt = time.Now()

	// 保存到文件
	return cm.saveCollection(collection)
}

// RemoveNodesFromCollection 从集合中移除节点
func (cm *CollectionManager) RemoveNodesFromCollection(collectionID string, nodeFPs []string) error {
	collection, exists := cm.collections[collectionID]
	if !exists {
		return fmt.Errorf("集合不存在: %s", collectionID)
	}

	// 移除节点
	removeFPs := make(map[string]bool)
	for _, fp := range nodeFPs {
		removeFPs[fp] = true
	}

	// 从NodeFPs中移除
	var newNodeFPs []string
	for _, fp := range collection.NodeFPs {
		if !removeFPs[fp] {
			newNodeFPs = append(newNodeFPs, fp)
		}
	}
	collection.NodeFPs = newNodeFPs

	// 从Sort中移除
	var newSort []string
	for _, fp := range collection.Sort {
		if !removeFPs[fp] {
			newSort = append(newSort, fp)
		}
	}
	collection.Sort = newSort

	collection.UpdatedAt = time.Now()

	// 保存到文件
	return cm.saveCollection(collection)
}

// SortNodesInCollection 排序集合中的节点
func (cm *CollectionManager) SortNodesInCollection(collectionID string, sortedFPs []string) error {
	collection, exists := cm.collections[collectionID]
	if !exists {
		return fmt.Errorf("集合不存在: %s", collectionID)
	}

	// 验证所有节点都在集合中
	existingFPs := make(map[string]bool)
	for _, fp := range collection.NodeFPs {
		existingFPs[fp] = true
	}

	for _, fp := range sortedFPs {
		if !existingFPs[fp] {
			return fmt.Errorf("节点不在集合中: %s", fp)
		}
	}

	collection.Sort = sortedFPs
	collection.UpdatedAt = time.Now()

	// 保存到文件
	return cm.saveCollection(collection)
}

// GetCollectionNodes 获取集合中的节点（按排序）
func (cm *CollectionManager) GetCollectionNodes(collectionID string) []string {
	collection, exists := cm.collections[collectionID]
	if !exists {
		return []string{}
	}

	// 如果有排序，返回排序后的列表
	if len(collection.Sort) > 0 {
		return collection.Sort
	}

	// 否则返回原始列表
	return collection.NodeFPs
}

// saveCollection 保存集合到文件
func (cm *CollectionManager) saveCollection(collection *models.Collection) error {
	collectionFile := cm.fss.GetPath(fmt.Sprintf("collections/%s.yml", collection.ID))
	return cm.fss.WriteJSON(collectionFile, collection)
}

// GetCollectionsByTag 根据标签获取集合
func (cm *CollectionManager) GetCollectionsByTag(tag string) []*models.Collection {
	var result []*models.Collection
	for _, collection := range cm.collections {
		for _, collectionTag := range collection.Tags {
			if collectionTag == tag {
				result = append(result, collection)
				break
			}
		}
	}
	return result
}

// GetCollectionStats 获取集合统计信息
func (cm *CollectionManager) GetCollectionStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_collections": len(cm.collections),
	}

	// 统计标签
	tags := make(map[string]int)
	for _, collection := range cm.collections {
		for _, tag := range collection.Tags {
			tags[tag]++
		}
	}
	stats["tags"] = tags

	// 统计节点数量分布
	nodeCounts := make(map[int]int)
	for _, collection := range cm.collections {
		count := len(collection.NodeFPs)
		nodeCounts[count]++
	}
	stats["node_counts"] = nodeCounts

	return stats
}
