package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// AuditManager 审计管理器
type AuditManager struct {
	fss *fss.FSS
}

// NewAuditManager 创建审计管理器
func NewAuditManager(fss *fss.FSS) *AuditManager {
	return &AuditManager{
		fss: fss,
	}
}

// LogAudit 记录审计日志
func (am *AuditManager) LogAudit(userID, action, resource, resourceID, details, ip, userAgent string) error {
	auditLog := &models.AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IP:         ip,
		UserAgent:  userAgent,
		Timestamp:  time.Now(),
	}

	return am.appendAuditLog(auditLog)
}

// LogAccess 记录访问日志
func (am *AuditManager) LogAccess(tokenHash, target, ip, userAgent string, status, size int) error {
	accessLog := &models.AccessLog{
		ID:        uuid.New().String(),
		TokenHash: tokenHash,
		Target:    target,
		IP:        ip,
		UserAgent: userAgent,
		Status:    status,
		Size:      size,
		Timestamp: time.Now(),
	}

	return am.appendAccessLog(accessLog)
}

// appendAuditLog 追加审计日志
func (am *AuditManager) appendAuditLog(log *models.AuditLog) error {
	// 确保目录存在
	if err := am.fss.EnsureDir("audit"); err != nil {
		return fmt.Errorf("创建审计目录失败: %w", err)
	}

	// 生成文件名（按月分割）
	filename := fmt.Sprintf("audit-%s.jsonl", time.Now().Format("2006-01"))
	filepath := am.fss.GetPath(fmt.Sprintf("audit/%s", filename))

	// 序列化日志
	data, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("序列化审计日志失败: %w", err)
	}

	// 追加到文件
	return am.appendToFile(filepath, data)
}

// appendAccessLog 追加访问日志
func (am *AuditManager) appendAccessLog(log *models.AccessLog) error {
	// 确保目录存在
	if err := am.fss.EnsureDir("access"); err != nil {
		return fmt.Errorf("创建访问日志目录失败: %w", err)
	}

	// 生成文件名（按月分割）
	filename := fmt.Sprintf("access-%s.jsonl", time.Now().Format("2006-01"))
	filepath := am.fss.GetPath(fmt.Sprintf("access/%s", filename))

	// 序列化日志
	data, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("序列化访问日志失败: %w", err)
	}

	// 追加到文件
	return am.appendToFile(filepath, data)
}

// appendToFile 追加到文件
func (am *AuditManager) appendToFile(filePath string, data []byte) error {
	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 打开文件进行追加
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 写入数据
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("写入数据失败: %w", err)
	}

	// 写入换行符
	if _, err := file.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("写入换行符失败: %w", err)
	}

	// 同步到磁盘
	if err := file.Sync(); err != nil {
		return fmt.Errorf("同步文件失败: %w", err)
	}

	return nil
}

// GetAuditLogs 获取审计日志
func (am *AuditManager) GetAuditLogs(startTime, endTime time.Time, userID, action string) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog

	// 获取时间范围内的所有审计日志文件
	files, err := am.getAuditFiles(startTime, endTime)
	if err != nil {
		return nil, err
	}

	// 读取并解析日志
	for _, file := range files {
		fileLogs, err := am.parseAuditFile(file, startTime, endTime, userID, action)
		if err != nil {
			logrus.Errorf("解析审计日志文件失败: %s, 错误: %v", file, err)
			continue
		}
		logs = append(logs, fileLogs...)
	}

	// 按时间戳降序排序（最新的在前）
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.After(logs[j].Timestamp)
	})

	return logs, nil
}

// GetAccessLogs 获取访问日志
func (am *AuditManager) GetAccessLogs(startTime, endTime time.Time, tokenHash, target string) ([]*models.AccessLog, error) {
	var logs []*models.AccessLog

	// 获取时间范围内的所有访问日志文件
	files, err := am.getAccessFiles(startTime, endTime)
	if err != nil {
		return nil, err
	}

	// 读取并解析日志
	for _, file := range files {
		fileLogs, err := am.parseAccessFile(file, startTime, endTime, tokenHash, target)
		if err != nil {
			logrus.Errorf("解析访问日志文件失败: %s, 错误: %v", file, err)
			continue
		}
		logs = append(logs, fileLogs...)
	}

	// 按时间戳降序排序（最新的在前）
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.After(logs[j].Timestamp)
	})

	return logs, nil
}

// getAuditFiles 获取审计日志文件列表
func (am *AuditManager) getAuditFiles(startTime, endTime time.Time) ([]string, error) {
	var files []string

	// 生成时间范围内的月份
	current := time.Date(startTime.Year(), startTime.Month(), 1, 0, 0, 0, 0, startTime.Location())
	end := time.Date(endTime.Year(), endTime.Month(), 1, 0, 0, 0, 0, endTime.Location())

	for current.Before(end) || current.Equal(end) {
		filename := fmt.Sprintf("audit-%s.jsonl", current.Format("2006-01"))
		filepath := am.fss.GetPath(fmt.Sprintf("audit/%s", filename))

		if am.fss.FileExists(fmt.Sprintf("audit/%s", filename)) {
			files = append(files, filepath)
		}

		// 移动到下个月
		current = current.AddDate(0, 1, 0)
	}

	return files, nil
}

// getAccessFiles 获取访问日志文件列表
func (am *AuditManager) getAccessFiles(startTime, endTime time.Time) ([]string, error) {
	var files []string

	// 生成时间范围内的月份
	current := time.Date(startTime.Year(), startTime.Month(), 1, 0, 0, 0, 0, startTime.Location())
	end := time.Date(endTime.Year(), endTime.Month(), 1, 0, 0, 0, 0, endTime.Location())

	for current.Before(end) || current.Equal(end) {
		filename := fmt.Sprintf("access-%s.jsonl", current.Format("2006-01"))
		filepath := am.fss.GetPath(fmt.Sprintf("access/%s", filename))

		if am.fss.FileExists(fmt.Sprintf("access/%s", filename)) {
			files = append(files, filepath)
		}

		// 移动到下个月
		current = current.AddDate(0, 1, 0)
	}

	return files, nil
}

// parseAuditFile 解析审计日志文件
func (am *AuditManager) parseAuditFile(filepath string, startTime, endTime time.Time, userID, action string) ([]*models.AuditLog, error) {
	data, err := am.fss.Read(filepath)
	if err != nil {
		return nil, err
	}

	var logs []*models.AuditLog
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var log models.AuditLog
		if err := json.Unmarshal([]byte(line), &log); err != nil {
			continue // 跳过无效行
		}

		// 时间过滤
		if log.Timestamp.Before(startTime) || log.Timestamp.After(endTime) {
			continue
		}

		// 用户ID过滤
		if userID != "" && log.UserID != userID {
			continue
		}

		// 操作过滤
		if action != "" && log.Action != action {
			continue
		}

		logs = append(logs, &log)
	}

	return logs, nil
}

// parseAccessFile 解析访问日志文件
func (am *AuditManager) parseAccessFile(filepath string, startTime, endTime time.Time, tokenHash, target string) ([]*models.AccessLog, error) {
	data, err := am.fss.Read(filepath)
	if err != nil {
		return nil, err
	}

	var logs []*models.AccessLog
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var log models.AccessLog
		if err := json.Unmarshal([]byte(line), &log); err != nil {
			continue // 跳过无效行
		}

		// 时间过滤
		if log.Timestamp.Before(startTime) || log.Timestamp.After(endTime) {
			continue
		}

		// 令牌哈希过滤
		if tokenHash != "" && log.TokenHash != tokenHash {
			continue
		}

		// 目标格式过滤
		if target != "" && log.Target != target {
			continue
		}

		logs = append(logs, &log)
	}

	return logs, nil
}

// GetAuditStats 获取审计统计
func (am *AuditManager) GetAuditStats(startTime, endTime time.Time) (map[string]interface{}, error) {
	logs, err := am.GetAuditLogs(startTime, endTime, "", "")
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_logs": len(logs),
	}

	// 按操作统计
	actionCounts := make(map[string]int)
	for _, log := range logs {
		actionCounts[log.Action]++
	}
	stats["actions"] = actionCounts

	// 按用户统计
	userCounts := make(map[string]int)
	for _, log := range logs {
		userCounts[log.UserID]++
	}
	stats["users"] = userCounts

	// 按资源统计
	resourceCounts := make(map[string]int)
	for _, log := range logs {
		resourceCounts[log.Resource]++
	}
	stats["resources"] = resourceCounts

	return stats, nil
}

// GetAccessStats 获取访问统计
func (am *AuditManager) GetAccessStats(startTime, endTime time.Time) (map[string]interface{}, error) {
	logs, err := am.GetAccessLogs(startTime, endTime, "", "")
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_requests": len(logs),
	}

	// 按状态码统计
	statusCounts := make(map[int]int)
	for _, log := range logs {
		statusCounts[log.Status]++
	}
	stats["status_codes"] = statusCounts

	// 按目标格式统计
	targetCounts := make(map[string]int)
	for _, log := range logs {
		targetCounts[log.Target]++
	}
	stats["targets"] = targetCounts

	// 总流量
	totalSize := 0
	for _, log := range logs {
		totalSize += log.Size
	}
	stats["total_size"] = totalSize

	return stats, nil
}

// GetWeeklyClientStats 获取一周内客户端统计（IP去重）
func (am *AuditManager) GetWeeklyClientStats() (map[string]interface{}, error) {
	// 计算一周前的时间
	oneWeekAgo := time.Now().AddDate(0, 0, -7)

	// 获取一周内的访问日志
	logs, err := am.GetAccessLogs(oneWeekAgo, time.Now(), "", "")
	if err != nil {
		return nil, err
	}

	// 使用map来去重IP地址
	uniqueIPs := make(map[string]bool)
	successfulRequests := 0

	for _, log := range logs {
		// 只统计成功的请求（状态码200-299）
		if log.Status >= 200 && log.Status < 300 {
			uniqueIPs[log.IP] = true
			successfulRequests++
		}
	}

	// 统计客户端类型
	clientTypes := make(map[string]int)
	for _, log := range logs {
		if log.Status >= 200 && log.Status < 300 {
			clientTypes[log.Target]++
		}
	}

	stats := map[string]interface{}{
		"unique_clients":      len(uniqueIPs),     // 去重后的客户端数量
		"total_requests":      len(logs),          // 总请求数
		"successful_requests": successfulRequests, // 成功请求数
		"client_types":        clientTypes,        // 按客户端类型统计
		"time_range": map[string]interface{}{
			"start": oneWeekAgo,
			"end":   time.Now(),
		},
	}

	return stats, nil
}
