package azure

import (
	"context"
	"fmt"
	"time"

	"proxy-distributor/internal/users"

	"github.com/sirupsen/logrus"
)

// AzureSyncManager Azure AD同步管理器
type AzureSyncManager struct {
	userManager  *users.UserManager
	tenantID     string
	clientID     string
	clientSecret string
}

// AzureConfig Azure AD配置
type AzureConfig struct {
	TenantID     string   `yaml:"tenant_id"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	GroupIDs     []string `yaml:"group_ids"`
	SyncInterval string   `yaml:"sync_interval"` // 如 "1h", "24h"
}

// NewAzureSyncManager 创建Azure AD同步管理器
func NewAzureSyncManager(userManager *users.UserManager, config *AzureConfig) (*AzureSyncManager, error) {
	// 注意：这是一个简化版本，实际使用时需要集成Azure SDK
	// 这里只提供基本的框架结构

	return &AzureSyncManager{
		userManager:  userManager,
		tenantID:     config.TenantID,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
	}, nil
}

// SyncGroupMembers 同步指定用户组的成员
func (asm *AzureSyncManager) SyncGroupMembers(groupID string) error {
	logrus.Infof("开始同步Azure AD用户组: %s", groupID)

	// 注意：这是一个简化版本，实际使用时需要调用Azure Graph API
	// 这里只提供基本的框架结构

	// 模拟获取组成员
	members := []*AzureUser{
		{
			ID:                "azure-user-1",
			UserPrincipalName: "user1@example.com",
			DisplayName:       "User One",
			GivenName:         "User",
			Surname:           "One",
			Mail:              "user1@example.com",
			JobTitle:          "Developer",
			Department:        "IT",
			Groups:            []string{groupID},
		},
	}

	logrus.Infof("从Azure AD获取到 %d 个用户", len(members))

	// 同步用户到本地系统
	syncedCount := 0
	for _, member := range members {
		if err := asm.syncUser(member); err != nil {
			logrus.Errorf("同步用户失败 %s: %v", member.UserPrincipalName, err)
			continue
		}
		syncedCount++
	}

	logrus.Infof("成功同步 %d 个用户", syncedCount)
	return nil
}

// getGroupMembers 获取组成员
func (asm *AzureSyncManager) getGroupMembers(ctx context.Context, groupID string) ([]*AzureUser, error) {
	// 注意：这是一个简化版本，实际使用时需要调用Azure Graph API
	// 这里返回模拟数据
	return []*AzureUser{}, nil
}

// AzureUser Azure AD用户信息
type AzureUser struct {
	ID                string   `json:"id"`
	UserPrincipalName string   `json:"userPrincipalName"`
	DisplayName       string   `json:"displayName"`
	GivenName         string   `json:"givenName"`
	Surname           string   `json:"surname"`
	Mail              string   `json:"mail"`
	JobTitle          string   `json:"jobTitle"`
	Department        string   `json:"department"`
	Groups            []string `json:"groups"`
}

// convertToAzureUser 转换Graph API用户对象
func (asm *AzureSyncManager) convertToAzureUser(item interface{}) *AzureUser {
	// 注意：这是一个简化版本，实际使用时需要根据Graph API响应结构进行转换
	return &AzureUser{
		ID:                "azure-user-id",
		UserPrincipalName: "user@domain.com",
		DisplayName:       "User Name",
		GivenName:         "User",
		Surname:           "Name",
		Mail:              "user@domain.com",
		JobTitle:          "Developer",
		Department:        "IT",
		Groups:            []string{"group1", "group2"},
	}
}

// syncUser 同步单个用户
func (asm *AzureSyncManager) syncUser(azureUser *AzureUser) error {
	// 检查用户是否已存在
	_, exists := asm.userManager.GetUser(azureUser.ID)

	if exists {
		// 更新现有用户信息
		_, err := asm.userManager.CreateOrUpdateUser(
			azureUser.ID,
			azureUser.UserPrincipalName,
			azureUser.DisplayName,
			[]string{"user"}, // 默认角色
		)
		if err != nil {
			return fmt.Errorf("更新用户失败: %w", err)
		}
		logrus.Debugf("更新用户: %s", azureUser.DisplayName)
	} else {
		// 创建新用户
		_, err := asm.userManager.CreateOrUpdateUser(
			azureUser.ID,
			azureUser.UserPrincipalName,
			azureUser.DisplayName,
			[]string{"user"}, // 默认角色
		)
		if err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}
		logrus.Debugf("创建新用户: %s", azureUser.DisplayName)
	}

	return nil
}

// StartPeriodicSync 启动定期同步
func (asm *AzureSyncManager) StartPeriodicSync(groupIDs []string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logrus.Infof("启动Azure AD定期同步，间隔: %v", interval)

	for {
		select {
		case <-ticker.C:
			for _, groupID := range groupIDs {
				if err := asm.SyncGroupMembers(groupID); err != nil {
					logrus.Errorf("同步用户组 %s 失败: %v", groupID, err)
				}
			}
		}
	}
}

// SyncAllGroups 同步所有配置的用户组
func (asm *AzureSyncManager) SyncAllGroups(groupIDs []string) error {
	for _, groupID := range groupIDs {
		if err := asm.SyncGroupMembers(groupID); err != nil {
			logrus.Errorf("同步用户组 %s 失败: %v", groupID, err)
			// 继续同步其他组，不因为一个组失败而停止
		}
	}
	return nil
}
