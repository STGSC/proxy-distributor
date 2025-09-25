package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Manager 通知渠道管理器
type Manager struct {
	fss *fss.FSS
}

// NewManager 创建通知渠道管理器
func NewManager(fss *fss.FSS) *Manager {
	return &Manager{
		fss: fss,
	}
}

// GetChannels 获取所有通知渠道
func (m *Manager) GetChannels() ([]*models.NotificationChannel, error) {
	channels := []*models.NotificationChannel{}

	// 从文件系统读取通知渠道数据
	data, err := m.fss.Read("notifications/channels.json")
	if err != nil {
		// 如果文件不存在，返回空列表
		return channels, nil
	}

	if err := json.Unmarshal(data, &channels); err != nil {
		return nil, fmt.Errorf("解析通知渠道数据失败: %w", err)
	}

	return channels, nil
}

// GetChannel 获取指定通知渠道
func (m *Manager) GetChannel(id string) (*models.NotificationChannel, bool) {
	channels, err := m.GetChannels()
	if err != nil {
		return nil, false
	}

	for _, channel := range channels {
		if channel.ID == id {
			return channel, true
		}
	}

	return nil, false
}

// CreateChannel 创建通知渠道
func (m *Manager) CreateChannel(name, webhookURL, format string) (*models.NotificationChannel, error) {
	channel := &models.NotificationChannel{
		ID:         uuid.New().String(),
		Name:       name,
		Type:       "webhook",
		WebhookURL: webhookURL,
		Format:     format,
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	channels, err := m.GetChannels()
	if err != nil {
		return nil, err
	}

	channels = append(channels, channel)

	if err := m.saveChannels(channels); err != nil {
		return nil, err
	}

	return channel, nil
}

// UpdateChannel 更新通知渠道
func (m *Manager) UpdateChannel(id, name, webhookURL, format string, enabled bool) error {
	channels, err := m.GetChannels()
	if err != nil {
		return err
	}

	for i, channel := range channels {
		if channel.ID == id {
			channels[i].Name = name
			channels[i].WebhookURL = webhookURL
			channels[i].Format = format
			channels[i].Enabled = enabled
			channels[i].UpdatedAt = time.Now()
			break
		}
	}

	return m.saveChannels(channels)
}

// DeleteChannel 删除通知渠道
func (m *Manager) DeleteChannel(id string) error {
	channels, err := m.GetChannels()
	if err != nil {
		return err
	}

	var newChannels []*models.NotificationChannel
	for _, channel := range channels {
		if channel.ID != id {
			newChannels = append(newChannels, channel)
		}
	}

	return m.saveChannels(newChannels)
}

// saveChannels 保存通知渠道数据
func (m *Manager) saveChannels(channels []*models.NotificationChannel) error {
	data, err := json.MarshalIndent(channels, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化通知渠道数据失败: %w", err)
	}

	if err := m.fss.AtomicWrite("notifications/channels.json", data); err != nil {
		return fmt.Errorf("保存通知渠道数据失败: %w", err)
	}

	return nil
}

// SendNotification 发送通知
func (m *Manager) SendNotification(channelID, title, message string) error {
	channel, exists := m.GetChannel(channelID)
	if !exists {
		return fmt.Errorf("通知渠道不存在: %s", channelID)
	}

	if !channel.Enabled {
		return fmt.Errorf("通知渠道已禁用: %s", channelID)
	}

	// 根据格式构建消息
	var payload []byte
	var err error

	switch channel.Format {
	case "dingtalk":
		payload, err = m.buildDingTalkMessage(title, message)
	case "lark":
		payload, err = m.buildLarkMessage(title, message)
	default:
		return fmt.Errorf("不支持的通知格式: %s", channel.Format)
	}

	if err != nil {
		return fmt.Errorf("构建通知消息失败: %w", err)
	}

	// 发送HTTP请求
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(channel.WebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("发送通知失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("通知发送失败，状态码: %d", resp.StatusCode)
	}

	logrus.Infof("通知发送成功: %s -> %s", channel.Name, title)
	return nil
}

// buildDingTalkMessage 构建钉钉消息
func (m *Manager) buildDingTalkMessage(title, message string) ([]byte, error) {
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  fmt.Sprintf("## %s\n\n%s", title, message),
		},
	}

	return json.Marshal(payload)
}

// buildLarkMessage 构建飞书消息
func (m *Manager) buildLarkMessage(title, message string) ([]byte, error) {
	payload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": fmt.Sprintf("%s\n%s", title, message),
		},
	}

	return json.Marshal(payload)
}

// CheckProviderExpiry 检查订阅源到期情况
func (m *Manager) CheckProviderExpiry(providers []*models.Provider) {
	now := time.Now()

	for _, provider := range providers {
		if provider.ExpiryDate == nil || provider.NotifyChannel == "" {
			continue
		}

		// 检查是否在到期前7天、3天、1天
		daysUntilExpiry := int(provider.ExpiryDate.Sub(now).Hours() / 24)

		if daysUntilExpiry == 7 || daysUntilExpiry == 3 || daysUntilExpiry == 1 {
			title := "订阅源到期提醒"
			message := fmt.Sprintf("订阅源 \"%s\" 将在 %d 天后到期 (%s)",
				provider.Name, daysUntilExpiry, provider.ExpiryDate.Format("2006-01-02 15:04:05"))

			if err := m.SendNotification(provider.NotifyChannel, title, message); err != nil {
				logrus.Errorf("发送到期提醒失败: %v", err)
			}
		}
	}
}
