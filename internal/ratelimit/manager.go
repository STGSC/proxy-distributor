package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/sirupsen/logrus"
)

// RateLimitManager 限流管理器
type RateLimitManager struct {
	fss     *fss.FSS
	states  map[string]*models.RateLimitState // 令牌哈希 -> 限流状态
	mutex   sync.RWMutex
	cleanup *time.Ticker
}

// NewRateLimitManager 创建限流管理器
func NewRateLimitManager(fss *fss.FSS) *RateLimitManager {
	rm := &RateLimitManager{
		fss:     fss,
		states:  make(map[string]*models.RateLimitState),
		cleanup: time.NewTicker(1 * time.Minute), // 每分钟清理一次
	}

	// 加载限流状态
	if err := rm.loadRateLimitStates(); err != nil {
		logrus.Errorf("加载限流状态失败: %v", err)
	}

	// 启动清理任务
	go rm.startCleanup()

	return rm
}

// CheckRateLimit 检查限流
func (rm *RateLimitManager) CheckRateLimit(tokenHash string, limit int) (bool, error) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	now := time.Now()
	state, exists := rm.states[tokenHash]

	if !exists {
		// 创建新的限流状态
		state = &models.RateLimitState{
			TokenHash: tokenHash,
			LastReset: now,
			Count:     0,
			Limit:     limit,
		}
		rm.states[tokenHash] = state
	}

	// 检查是否需要重置计数器
	if now.Sub(state.LastReset) >= time.Minute {
		state.Count = 0
		state.LastReset = now
	}

	// 检查是否超过限制
	if state.Count >= state.Limit {
		return false, nil
	}

	// 增加计数
	state.Count++

	return true, nil
}

// GetRateLimitState 获取限流状态
func (rm *RateLimitManager) GetRateLimitState(tokenHash string) (*models.RateLimitState, bool) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	state, exists := rm.states[tokenHash]
	if !exists {
		return nil, false
	}

	// 返回副本
	stateCopy := *state
	return &stateCopy, true
}

// SetRateLimit 设置限流
func (rm *RateLimitManager) SetRateLimit(tokenHash string, limit int) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	state, exists := rm.states[tokenHash]
	if !exists {
		state = &models.RateLimitState{
			TokenHash: tokenHash,
			LastReset: time.Now(),
			Count:     0,
			Limit:     limit,
		}
	} else {
		state.Limit = limit
	}

	rm.states[tokenHash] = state
}

// ResetRateLimit 重置限流
func (rm *RateLimitManager) ResetRateLimit(tokenHash string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if state, exists := rm.states[tokenHash]; exists {
		state.Count = 0
		state.LastReset = time.Now()
	}
}

// RemoveRateLimit 移除限流
func (rm *RateLimitManager) RemoveRateLimit(tokenHash string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.states, tokenHash)
}

// GetAllRateLimitStates 获取所有限流状态
func (rm *RateLimitManager) GetAllRateLimitStates() map[string]*models.RateLimitState {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	states := make(map[string]*models.RateLimitState)
	for tokenHash, state := range rm.states {
		stateCopy := *state
		states[tokenHash] = &stateCopy
	}

	return states
}

// GetRateLimitStats 获取限流统计
func (rm *RateLimitManager) GetRateLimitStats() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_tokens": len(rm.states),
	}

	// 统计限制分布
	limitCounts := make(map[int]int)
	activeCount := 0
	blockedCount := 0

	now := time.Now()
	for _, state := range rm.states {
		limitCounts[state.Limit]++

		// 检查是否在限制期内
		if now.Sub(state.LastReset) < time.Minute {
			if state.Count >= state.Limit {
				blockedCount++
			} else {
				activeCount++
			}
		} else {
			activeCount++
		}
	}

	stats["limit_distribution"] = limitCounts
	stats["active_tokens"] = activeCount
	stats["blocked_tokens"] = blockedCount

	return stats
}

// loadRateLimitStates 加载限流状态
func (rm *RateLimitManager) loadRateLimitStates() error {
	stateFile := rm.fss.GetPath("state/ratelimit.gob")

	if !rm.fss.FileExists("state/ratelimit.gob") {
		return nil // 文件不存在，使用空状态
	}

	return rm.fss.ReadGob(stateFile, &rm.states)
}

// saveRateLimitStates 保存限流状态
func (rm *RateLimitManager) saveRateLimitStates() error {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stateFile := rm.fss.GetPath("state/ratelimit.gob")

	// 确保目录存在
	if err := rm.fss.EnsureDir("state"); err != nil {
		return fmt.Errorf("创建状态目录失败: %w", err)
	}

	return rm.fss.WriteGob(stateFile, rm.states)
}

// startCleanup 启动清理任务
func (rm *RateLimitManager) startCleanup() {
	for range rm.cleanup.C {
		rm.cleanupExpiredStates()
		rm.saveRateLimitStates()
	}
}

// cleanupExpiredStates 清理过期的限流状态
func (rm *RateLimitManager) cleanupExpiredStates() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	now := time.Now()
	expiredTokens := []string{}

	for tokenHash, state := range rm.states {
		// 如果超过1小时没有活动，则清理
		if now.Sub(state.LastReset) > time.Hour {
			expiredTokens = append(expiredTokens, tokenHash)
		}
	}

	// 删除过期的状态
	for _, tokenHash := range expiredTokens {
		delete(rm.states, tokenHash)
	}

	if len(expiredTokens) > 0 {
		logrus.Infof("清理了 %d 个过期的限流状态", len(expiredTokens))
	}
}

// Stop 停止限流管理器
func (rm *RateLimitManager) Stop() {
	rm.cleanup.Stop()
	rm.saveRateLimitStates()
}

// TokenBucket 令牌桶限流器
type TokenBucket struct {
	capacity   int       // 桶容量
	tokens     int       // 当前令牌数
	lastRefill time.Time // 上次补充时间
	refillRate int       // 每秒补充速率
	mutex      sync.Mutex
}

// NewTokenBucket 创建令牌桶
func NewTokenBucket(capacity, refillRate int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
		refillRate: refillRate,
	}
}

// TryConsume 尝试消费令牌
func (tb *TokenBucket) TryConsume(tokens int) bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	// 补充令牌
	tb.refill()

	// 检查是否有足够的令牌
	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

// refill 补充令牌
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)

	// 计算应该补充的令牌数
	tokensToAdd := int(elapsed.Seconds()) * tb.refillRate

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// GetTokens 获取当前令牌数
func (tb *TokenBucket) GetTokens() int {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	tb.refill()
	return tb.tokens
}

// GetCapacity 获取桶容量
func (tb *TokenBucket) GetCapacity() int {
	return tb.capacity
}

// GetRefillRate 获取补充速率
func (tb *TokenBucket) GetRefillRate() int {
	return tb.refillRate
}
