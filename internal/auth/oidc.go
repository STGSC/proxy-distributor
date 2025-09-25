package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"proxy-distributor/internal/config"
	"proxy-distributor/internal/models"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// OIDCManager OIDC认证管理器
type OIDCManager struct {
	config        *config.AuthConfig
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	codeVerifiers map[string]string // state -> code_verifier
}

// Session 会话信息
type Session struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	UPN         string    `json:"upn"`
	DisplayName string    `json:"display_name"`
	Roles       []string  `json:"roles"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Claims JWT声明
type Claims struct {
	Session *Session `json:"session"`
	jwt.RegisteredClaims
}

// NewOIDCManager 创建OIDC管理器
func NewOIDCManager(cfg *config.AuthConfig) (*OIDCManager, error) {
	ctx := context.Background()

	// 构建OIDC发现端点URL
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.OIDC.TenantID)

	// 创建OIDC提供者
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("创建OIDC提供者失败: %w", err)
	}

	// 创建OAuth2配置
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "openid", "User.Read"},
	}

	// 创建ID Token验证器
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.OIDC.ClientID,
	})

	return &OIDCManager{
		config:        cfg,
		provider:      provider,
		oauth2Config:  oauth2Config,
		verifier:      verifier,
		codeVerifiers: make(map[string]string),
	}, nil
}

// GetAuthURL 获取认证URL
func (m *OIDCManager) GetAuthURL(state string) string {
	// 生成PKCE code verifier和challenge
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// 存储code verifier以便后续使用
	m.codeVerifiers[state] = codeVerifier

	// 构建认证URL
	authURL := m.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("response_mode", "query"),
	)

	return authURL
}

// ExchangeCode 交换授权码
func (m *OIDCManager) ExchangeCode(ctx context.Context, code, state string) (*Session, error) {
	// 获取存储的code verifier
	codeVerifier, exists := m.codeVerifiers[state]
	if !exists {
		return nil, fmt.Errorf("未找到对应的code verifier")
	}

	// 交换授权码获取令牌
	token, err := m.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("交换授权码失败: %w", err)
	}

	// 清理已使用的code verifier
	delete(m.codeVerifiers, state)

	// 验证ID Token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("未找到ID Token")
	}

	// 验证ID Token
	verifiedToken, err := m.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("验证ID Token失败: %w", err)
	}

	// 解析用户信息
	var claims struct {
		Subject           string   `json:"sub"`
		UPN               string   `json:"upn"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		GivenName         string   `json:"given_name"`
		FamilyName        string   `json:"family_name"`
		Roles             []string `json:"roles"`
		Groups            []string `json:"groups"`
		PreferredUsername string   `json:"preferred_username"`
	}

	if err := verifiedToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("解析ID Token声明失败: %w", err)
	}

	// 确定UPN值，优先使用upn字段，如果没有则使用preferred_username或email
	upn := claims.UPN
	if upn == "" {
		upn = claims.PreferredUsername
	}
	if upn == "" {
		upn = claims.Email
	}

	// 记录调试信息
	logrus.Debugf("OIDC Claims - Subject: %s, UPN: %s, PreferredUsername: %s, Email: %s, Name: %s",
		claims.Subject, claims.UPN, claims.PreferredUsername, claims.Email, claims.Name)
	logrus.Debugf("最终UPN值: %s", upn)

	// 构建会话信息
	session := &Session{
		ID:          uuid.New().String(),
		UserID:      claims.Subject,
		UPN:         upn,
		DisplayName: claims.Name,
		Roles:       claims.Roles,
		ExpiresAt:   time.Now().Add(24 * time.Hour), // 24小时过期
	}

	return session, nil
}

// CreateSessionToken 创建会话令牌
func (m *OIDCManager) CreateSessionToken(session *Session) (string, error) {
	claims := &Claims{
		Session: session,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        session.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.Session.Secret))
}

// ValidateSessionToken 验证会话令牌
func (m *OIDCManager) ValidateSessionToken(tokenString string) (*Session, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return []byte(m.config.Session.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("解析令牌失败: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims.Session, nil
	}

	return nil, fmt.Errorf("无效的令牌")
}

// LoginHandler 登录处理器
func (m *OIDCManager) LoginHandler(c *gin.Context) {
	// 生成状态参数
	state := generateState()

	// 生成认证URL
	authURL := m.GetAuthURL(state)

	// 重定向到认证URL
	c.Redirect(http.StatusFound, authURL)
}

// CallbackHandler 回调处理器
func (m *OIDCManager) CallbackHandler(c *gin.Context) {
	// 获取授权码和状态
	code := c.Query("code")
	state := c.Query("state")

	if code == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: "缺少授权码",
		})
		return
	}

	// 交换授权码获取会话
	session, err := m.ExchangeCode(c.Request.Context(), code, state)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("认证失败: %v", err),
		})
		return
	}

	// 创建会话令牌
	token, err := m.CreateSessionToken(session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("创建会话失败: %v", err),
		})
		return
	}

	// 设置Cookie
	c.SetCookie(
		m.config.Session.CookieName,
		token,
		24*3600, // 24小时
		"/",
		"",
		false, // 允许HTTP（开发环境）
		true,  // HttpOnly
	)

	// 重定向到主页
	c.Redirect(http.StatusFound, "/")
}

// LogoutHandler 登出处理器
func (m *OIDCManager) LogoutHandler(c *gin.Context) {
	// 清除Cookie
	c.SetCookie(
		m.config.Session.CookieName,
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	// 重定向到登录页
	c.Redirect(http.StatusFound, "/login")
}

// RequireAuth 认证中间件
func (m *OIDCManager) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从Cookie获取令牌
		token, err := c.Cookie(m.config.Session.CookieName)
		if err != nil {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    401,
				Message: "未认证",
			})
			c.Abort()
			return
		}

		// 验证令牌
		session, err := m.ValidateSessionToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    401,
				Message: "无效的会话",
			})
			c.Abort()
			return
		}

		// 将会话信息存储到上下文
		c.Set("session", session)
		c.Next()
	}
}

// RequireRole 角色权限中间件
func (m *OIDCManager) RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, exists := c.Get("session")
		if !exists {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    401,
				Message: "未认证",
			})
			c.Abort()
			return
		}

		sess := session.(*Session)

		// 检查用户是否具有所需角色
		hasRole := false
		for _, requiredRole := range requiredRoles {
			for _, userRole := range sess.Roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Code:    403,
				Message: "权限不足",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetCurrentUser 获取当前用户信息
func (m *OIDCManager) GetCurrentUser(c *gin.Context) (*Session, bool) {
	session, exists := c.Get("session")
	if !exists {
		return nil, false
	}
	return session.(*Session), true
}

// 辅助函数

// generateState 生成状态参数
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// generateCodeVerifier 生成PKCE code verifier
func generateCodeVerifier() string {
	// 生成32字节随机数据，base64编码后约43字符，符合PKCE规范
	b := make([]byte, 32)
	rand.Read(b)
	// 使用URL安全的base64编码，不包含填充
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

// generateCodeChallenge 生成PKCE code challenge
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	// 使用URL安全的base64编码，不包含填充
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
