package subscribe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/sirupsen/logrus"
)

// TokenManager 订阅令牌管理器
type TokenManager struct {
	fss    *fss.FSS
	tokens map[string]*models.SubscriptionToken // 令牌哈希 -> 令牌信息
}

// NewTokenManager 创建令牌管理器
func NewTokenManager(fss *fss.FSS) *TokenManager {
	tm := &TokenManager{
		fss:    fss,
		tokens: make(map[string]*models.SubscriptionToken),
	}

	// 加载现有令牌
	if err := tm.loadTokens(); err != nil {
		logrus.Errorf("加载令牌失败: %v", err)
	}

	return tm
}

// loadTokens 加载令牌数据
func (tm *TokenManager) loadTokens() error {
	tokensFile := tm.fss.GetPath("tokens/tokens.json")

	// 如果文件不存在，创建默认配置
	if !tm.fss.FileExists("tokens/tokens.json") {
		defaultTokens := map[string]interface{}{
			"version": 1,
			"list":    []*models.SubscriptionToken{},
		}
		if err := tm.fss.EnsureDir("tokens"); err != nil {
			return fmt.Errorf("创建令牌目录失败: %w", err)
		}
		if err := tm.fss.WriteJSON(tokensFile, defaultTokens); err != nil {
			return fmt.Errorf("创建默认令牌配置失败: %w", err)
		}
	}

	// 读取令牌配置
	var data struct {
		Version int                         `json:"version"`
		List    []*models.SubscriptionToken `json:"list"`
	}

	if err := tm.fss.ReadJSON(tokensFile, &data); err != nil {
		return fmt.Errorf("读取令牌配置失败: %w", err)
	}

	// 加载到内存
	tm.tokens = make(map[string]*models.SubscriptionToken)
	for _, token := range data.List {
		tm.tokens[token.TokenHash] = token
	}

	return nil
}

// saveTokens 保存令牌数据
func (tm *TokenManager) saveTokens() error {
	tokensFile := tm.fss.GetPath("tokens/tokens.json")

	var tokens []*models.SubscriptionToken
	for _, token := range tm.tokens {
		tokens = append(tokens, token)
	}

	data := map[string]interface{}{
		"version": 1,
		"list":    tokens,
	}

	return tm.fss.WriteJSON(tokensFile, data)
}

// GenerateToken 生成订阅令牌
func (tm *TokenManager) GenerateToken(userID string, rpm int, validDays int, clientName, clientType string) (*models.SubscriptionToken, error) {
	// 生成随机令牌
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("生成随机令牌失败: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)

	// 生成令牌哈希
	hash := sha256.Sum256([]byte(token))
	tokenHash := fmt.Sprintf("sha256:%x", hash)

	// 计算有效期
	validTo := time.Now().AddDate(0, 0, validDays)

	// 创建令牌对象
	subscriptionToken := &models.SubscriptionToken{
		UID:        userID,
		Token:      token, // 仅在生成时存储明文
		TokenHash:  tokenHash,
		Status:     "active",
		ValidTo:    validTo,
		RPM:        rpm,
		ClientName: clientName,
		ClientType: clientType,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// 保存到内存
	tm.tokens[tokenHash] = subscriptionToken

	// 保存到文件
	if err := tm.saveTokens(); err != nil {
		return nil, err
	}

	// 返回令牌对象（包含明文令牌）
	return subscriptionToken, nil
}

// ValidateToken 验证令牌
func (tm *TokenManager) ValidateToken(token string) (*models.SubscriptionToken, error) {
	// 计算令牌哈希
	hash := sha256.Sum256([]byte(token))
	tokenHash := fmt.Sprintf("sha256:%x", hash)

	// 查找令牌
	subscriptionToken, exists := tm.tokens[tokenHash]
	if !exists {
		return nil, fmt.Errorf("令牌不存在")
	}

	// 检查状态
	if subscriptionToken.Status != "active" {
		return nil, fmt.Errorf("令牌已失效")
	}

	// 检查有效期
	if time.Now().After(subscriptionToken.ValidTo) {
		return nil, fmt.Errorf("令牌已过期")
	}

	return subscriptionToken, nil
}

// RevokeToken 吊销令牌
func (tm *TokenManager) RevokeToken(token string) error {
	// 计算令牌哈希
	hash := sha256.Sum256([]byte(token))
	tokenHash := fmt.Sprintf("sha256:%x", hash)

	// 查找令牌
	subscriptionToken, exists := tm.tokens[tokenHash]
	if !exists {
		return fmt.Errorf("令牌不存在")
	}

	// 更新状态
	subscriptionToken.Status = "revoked"
	subscriptionToken.UpdatedAt = time.Now()

	// 保存到文件
	return tm.saveTokens()
}

// RevokeTokenByHash 通过哈希吊销令牌
func (tm *TokenManager) RevokeTokenByHash(tokenHash string) error {
	// 查找令牌
	subscriptionToken, exists := tm.tokens[tokenHash]
	if !exists {
		return fmt.Errorf("令牌不存在")
	}

	// 更新状态
	subscriptionToken.Status = "revoked"
	subscriptionToken.UpdatedAt = time.Now()

	// 保存到文件
	return tm.saveTokens()
}

// GetUserTokens 获取用户的所有令牌
func (tm *TokenManager) GetUserTokens(userID string) []*models.SubscriptionToken {
	var tokens []*models.SubscriptionToken
	for _, token := range tm.tokens {
		if token.UID == userID {
			// 不返回明文令牌，但保留其他信息
			tokenCopy := *token
			tokenCopy.Token = ""
			tokens = append(tokens, &tokenCopy)
		}
	}
	return tokens
}

// GetUserTokensWithURLs 获取用户的所有令牌（包含订阅链接）
func (tm *TokenManager) GetUserTokensWithURLs(userID string, baseURL string) []map[string]interface{} {
	var tokens []map[string]interface{}
	for _, token := range tm.tokens {
		if token.UID == userID {
			// 创建包含订阅链接的令牌信息
			tokenInfo := map[string]interface{}{
				"uid":         token.UID,
				"token":       token.Token, // 添加原始token
				"token_hash":  token.TokenHash,
				"status":      token.Status,
				"valid_to":    token.ValidTo,
				"rpm":         token.RPM,
				"client_name": token.ClientName, // 添加客户端名称
				"client_type": token.ClientType, // 添加客户端类型
				"created_at":  token.CreatedAt,
				"updated_at":  token.UpdatedAt,
			}

			// 如果令牌是活跃的，生成订阅链接
			if token.Status == "active" {
				subscriptionURL := fmt.Sprintf("%s/sub/%s?target=clash", baseURL, token.Token)
				tokenInfo["subscription_url"] = subscriptionURL
			}

			tokens = append(tokens, tokenInfo)
		}
	}
	return tokens
}

// GetTokenByHash 根据哈希获取令牌
func (tm *TokenManager) GetTokenByHash(tokenHash string) (*models.SubscriptionToken, bool) {
	token, exists := tm.tokens[tokenHash]
	if !exists {
		return nil, false
	}

	// 不返回明文令牌
	tokenCopy := *token
	tokenCopy.Token = ""
	return &tokenCopy, true
}

// CleanupExpiredTokens 清理过期令牌
func (tm *TokenManager) CleanupExpiredTokens() error {
	now := time.Now()
	cleaned := false

	for _, token := range tm.tokens {
		if now.After(token.ValidTo) && token.Status == "active" {
			token.Status = "expired"
			token.UpdatedAt = now
			cleaned = true
		}
	}

	if cleaned {
		return tm.saveTokens()
	}

	return nil
}

// GetTokenStats 获取令牌统计信息
func (tm *TokenManager) GetTokenStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_tokens": len(tm.tokens),
	}

	// 按状态统计
	statusCounts := make(map[string]int)
	for _, token := range tm.tokens {
		statusCounts[token.Status]++
	}
	stats["status_distribution"] = statusCounts

	// 按用户统计
	userCounts := make(map[string]int)
	for _, token := range tm.tokens {
		userCounts[token.UID]++
	}
	stats["user_distribution"] = userCounts

	// 按RPM统计
	rpmCounts := make(map[int]int)
	for _, token := range tm.tokens {
		rpmCounts[token.RPM]++
	}
	stats["rpm_distribution"] = rpmCounts

	return stats
}
