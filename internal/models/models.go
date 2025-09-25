package models

import (
	"time"
)

// Node 节点模型
type Node struct {
	Fingerprint string            `json:"fingerprint"` // 节点指纹（用于去重）
	Protocol    string            `json:"protocol"`    // 协议类型：vmess, vless, ss, trojan, etc.
	Host        string            `json:"host"`        // 主机地址
	Port        int               `json:"port"`        // 端口
	Params      map[string]string `json:"params"`      // 协议参数
	GeoCountry  string            `json:"geo_country"` // 国家
	GeoCity     string            `json:"geo_city"`    // 城市
	Name        string            `json:"name"`        // 节点名称
	Tags        []string          `json:"tags"`        // 标签
	ProviderID  string            `json:"provider_id"` // 来源订阅源ID
	CreatedAt   time.Time         `json:"created_at"`  // 创建时间
	UpdatedAt   time.Time         `json:"updated_at"`  // 更新时间
}

// Provider 订阅源
type Provider struct {
	ID            string     `json:"id" yaml:"id"`
	Name          string     `json:"name" yaml:"name"`
	URL           string     `json:"url" yaml:"url"`
	FetchCron     string     `json:"fetch_cron" yaml:"fetch_cron"`
	AuthHeader    string     `json:"auth_header,omitempty" yaml:"auth_header,omitempty"`
	Proxy         string     `json:"proxy,omitempty" yaml:"proxy,omitempty"`
	LastFetch     time.Time  `json:"last_fetch,omitempty" yaml:"last_fetch,omitempty"`
	LastSuccess   time.Time  `json:"last_success,omitempty" yaml:"last_success,omitempty"`
	Status        string     `json:"status" yaml:"status"` // active, disabled, error
	ErrorMsg      string     `json:"error_msg,omitempty" yaml:"error_msg,omitempty"`
	ExpiryDate    *time.Time `json:"expiry_date,omitempty" yaml:"expiry_date,omitempty"`       // 到期日期
	NotifyChannel string     `json:"notify_channel,omitempty" yaml:"notify_channel,omitempty"` // 通知渠道ID
}

// Collection 节点集合
type Collection struct {
	ID        string    `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
	NodeFPs   []string  `json:"node_fps" yaml:"node_fps"` // 节点指纹列表
	Sort      []string  `json:"sort" yaml:"sort"`         // 排序后的节点指纹
	Tags      []string  `json:"tags" yaml:"tags"`         // 集合标签
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// User 用户模型
type User struct {
	Subject     string    `json:"subject"`      // OIDC subject
	UPN         string    `json:"upn"`          // 用户主体名称
	DisplayName string    `json:"display_name"` // 显示名称
	Collections []string  `json:"collections"`  // 个人集合列表
	Roles       []string  `json:"roles"`        // 用户角色
	Disabled    bool      `json:"disabled"`     // 是否被禁用
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Role 角色模型
type Role struct {
	ID          string    `json:"id" yaml:"id"`
	Name        string    `json:"name" yaml:"name"`
	Collections []string  `json:"collections" yaml:"collections"` // 角色绑定的集合
	Permissions []string  `json:"permissions" yaml:"permissions"` // 角色权限
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" yaml:"updated_at"`
}

// SubscriptionToken 订阅令牌
type SubscriptionToken struct {
	UID        string    `json:"uid"`         // 用户ID
	Token      string    `json:"token"`       // 明文令牌（仅生成时使用）
	TokenHash  string    `json:"token_hash"`  // 令牌哈希
	Status     string    `json:"status"`      // active, revoked
	ValidTo    time.Time `json:"valid_to"`    // 有效期
	RPM        int       `json:"rpm"`         // 每分钟请求限制
	ClientName string    `json:"client_name"` // 客户端名称
	ClientType string    `json:"client_type"` // 客户端类型：clash, v2rayn, singbox, sip008
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AuditLog 审计日志
type AuditLog struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Action     string    `json:"action"`      // 操作类型
	Resource   string    `json:"resource"`    // 资源类型
	ResourceID string    `json:"resource_id"` // 资源ID
	Details    string    `json:"details"`     // 操作详情
	IP         string    `json:"ip"`          // 客户端IP
	UserAgent  string    `json:"user_agent"`  // 用户代理
	Timestamp  time.Time `json:"timestamp"`
}

// AccessLog 访问日志
type AccessLog struct {
	ID        string    `json:"id"`
	TokenHash string    `json:"token_hash"` // 令牌哈希（匿名）
	Target    string    `json:"target"`     // 导出格式
	IP        string    `json:"ip"`         // 客户端IP
	UserAgent string    `json:"user_agent"` // 用户代理
	Status    int       `json:"status"`     // HTTP状态码
	Size      int       `json:"size"`       // 响应大小
	Timestamp time.Time `json:"timestamp"`
}

// WALRecord WAL记录
type WALRecord struct {
	Op        string      `json:"op"`   // upsert, delete
	Type      string      `json:"type"` // node, collection, user, etc.
	ID        string      `json:"id"`   // 资源ID
	Data      interface{} `json:"data"` // 数据
	Timestamp time.Time   `json:"timestamp"`
}

// NodeUpsertRecord 节点更新记录
type NodeUpsertRecord struct {
	Op   string `json:"op"`
	FP   string `json:"fp"` // 节点指纹
	Node *Node  `json:"node"`
}

// NodeDeleteRecord 节点删除记录
type NodeDeleteRecord struct {
	Op string `json:"op"`
	FP string `json:"fp"` // 节点指纹
}

// SubscriptionRequest 订阅请求
type SubscriptionRequest struct {
	Target    string `json:"target"`    // 导出格式：clash, v2rayn, singbox, sip008
	Watermark bool   `json:"watermark"` // 是否添加水印
}

// APIResponse 统一API响应
type APIResponse struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

// PaginationRequest 分页请求
type PaginationRequest struct {
	Page     int    `json:"page" form:"page"`
	PageSize int    `json:"page_size" form:"page_size"`
	Sort     string `json:"sort" form:"sort"`
	Order    string `json:"order" form:"order"` // asc, desc
}

// PaginationResponse 分页响应
type PaginationResponse struct {
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Total    int64       `json:"total"`
	Items    interface{} `json:"items"`
}

// NodeFilter 节点过滤器
type NodeFilter struct {
	Protocol string   `json:"protocol" form:"protocol"`
	Country  string   `json:"country" form:"country"`
	Query    string   `json:"q" form:"q"`
	Tags     []string `json:"tags" form:"tags"`
}

// RateLimitState 限流状态
type RateLimitState struct {
	TokenHash string    `json:"token_hash"`
	LastReset time.Time `json:"last_reset"`
	Count     int       `json:"count"`
	Limit     int       `json:"limit"`
}

// ETagCache ETag缓存
type ETagCache struct {
	TokenHash string    `json:"token_hash"`
	Target    string    `json:"target"`
	ETag      string    `json:"etag"`
	Hash      string    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
}

// NotificationChannel 通知渠道
type NotificationChannel struct {
	ID         string    `json:"id" yaml:"id"`
	Name       string    `json:"name" yaml:"name"`
	Type       string    `json:"type" yaml:"type"` // webhook
	WebhookURL string    `json:"webhook_url" yaml:"webhook_url"`
	Format     string    `json:"format" yaml:"format"` // dingtalk, lark
	Enabled    bool      `json:"enabled" yaml:"enabled"`
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" yaml:"updated_at"`
}
