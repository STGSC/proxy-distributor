package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxy-distributor/internal/audit"
	"proxy-distributor/internal/auth"
	"proxy-distributor/internal/collections"
	"proxy-distributor/internal/config"
	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"
	"proxy-distributor/internal/nodes"
	"proxy-distributor/internal/notifications"
	"proxy-distributor/internal/providers"
	"proxy-distributor/internal/subscribe"
	"proxy-distributor/internal/users"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Server Web服务器
type Server struct {
	config              *config.Config
	fss                 *fss.FSS
	oidcManager         *auth.OIDCManager
	providerManager     *providers.ProviderManager
	nodeManager         *nodes.NodeManager
	collectionManager   *collections.CollectionManager
	userManager         *users.UserManager
	exporter            *subscribe.Exporter
	tokenManager        *subscribe.TokenManager
	auditManager        *audit.AuditManager
	notificationManager *notifications.Manager
	router              *gin.Engine
}

// NewServer 创建Web服务器
func NewServer(cfg *config.Config) *Server {
	// 初始化文件存储系统
	fss := fss.New(cfg.DataDir)

	// 初始化各个管理器
	oidcManager, err := auth.NewOIDCManager(&cfg.Auth)
	if err != nil {
		logrus.Fatalf("初始化OIDC管理器失败: %v", err)
	}

	providerManager := providers.NewProviderManager(fss)
	nodeManager := nodes.NewNodeManager(fss)
	collectionManager := collections.NewCollectionManager(fss)
	userManager := users.NewUserManager(fss)
	exporter := subscribe.NewExporter(fss, nodeManager, collectionManager, userManager)
	tokenManager := subscribe.NewTokenManager(fss)
	auditManager := audit.NewAuditManager(fss)
	notificationManager := notifications.NewManager(fss)

	// 设置节点管理器到订阅源管理器
	providerManager.SetNodeManager(nodeManager)

	// 加载订阅源
	if err := providerManager.LoadProviders(); err != nil {
		logrus.Errorf("加载订阅源失败: %v", err)
	}

	server := &Server{
		config:              cfg,
		fss:                 fss,
		oidcManager:         oidcManager,
		providerManager:     providerManager,
		nodeManager:         nodeManager,
		collectionManager:   collectionManager,
		userManager:         userManager,
		exporter:            exporter,
		tokenManager:        tokenManager,
		auditManager:        auditManager,
		notificationManager: notificationManager,
	}

	// 设置路由
	server.setupRoutes()

	return server
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 设置Gin模式
	if s.config.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	s.router = gin.New()
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())

	// 静态文件服务
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")

	// 认证路由
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.oidcManager.LoginHandler)
		auth.GET("/callback", s.oidcManager.CallbackHandler)
		auth.GET("/logout", s.oidcManager.LogoutHandler)
	}

	// API路由
	api := s.router.Group("/api")
	api.Use(s.oidcManager.RequireAuth())
	{
		// 用户信息
		api.GET("/me", s.getCurrentUser)

		// 订阅源管理
		providers := api.Group("/providers")
		{
			providers.GET("", s.requirePermission("manage_providers", s.getProviders))
			providers.POST("", s.requirePermission("manage_providers", s.createProvider))
			providers.GET("/:id", s.requirePermission("manage_providers", s.getProvider))
			providers.PUT("/:id", s.requirePermission("manage_providers", s.updateProvider))
			providers.DELETE("/:id", s.requirePermission("manage_providers", s.deleteProvider))
			providers.POST("/:id/refresh", s.requirePermission("manage_providers", s.refreshProvider))
			providers.POST("/:id/disable", s.requirePermission("manage_providers", s.disableProvider))
			providers.POST("/:id/enable", s.requirePermission("manage_providers", s.enableProvider))
		}

		// 节点管理
		nodes := api.Group("/nodes")
		{
			nodes.GET("", s.requirePermission("manage_collections", s.getNodes))
			nodes.POST("", s.requirePermission("manage_collections", s.createNode))
			nodes.GET("/:id", s.requirePermission("manage_collections", s.getNode))
			nodes.PUT("/:id", s.requirePermission("manage_collections", s.updateNode))
			nodes.DELETE("/:id", s.requirePermission("manage_collections", s.deleteNode))
			nodes.GET("/stats", s.requirePermission("manage_collections", s.getNodeStats))
			nodes.GET("/countries", s.requirePermission("manage_collections", s.getCountries))
			nodes.GET("/cities", s.requirePermission("manage_collections", s.getCities))
			nodes.POST("/batch-add-to-collection", s.requirePermission("manage_collections", s.batchAddNodesToCollection))
		}

		// 集合管理
		collections := api.Group("/collections")
		{
			collections.GET("", s.requirePermission("manage_collections", s.getCollections))
			collections.POST("", s.requirePermission("manage_collections", s.createCollection))
			collections.GET("/:id", s.requirePermission("manage_collections", s.getCollection))
			collections.PUT("/:id", s.requirePermission("manage_collections", s.updateCollection))
			collections.DELETE("/:id", s.requirePermission("manage_collections", s.deleteCollection))
			collections.POST("/:id/nodes", s.requirePermission("manage_collections", s.addNodesToCollection))
			collections.DELETE("/:id/nodes", s.requirePermission("manage_collections", s.removeNodesFromCollection))
			collections.PUT("/:id/sort", s.requirePermission("manage_collections", s.sortCollectionNodes))
		}

		// 角色管理
		roles := api.Group("/roles")
		{
			roles.GET("", s.requirePermission("manage_users", s.getRoles))
			roles.POST("", s.requirePermission("manage_users", s.createRole))
			roles.GET("/:id", s.requirePermission("manage_users", s.getRole))
			roles.PUT("/:id", s.requirePermission("manage_users", s.updateRole))
			roles.DELETE("/:id", s.requirePermission("manage_users", s.deleteRole))
			roles.PUT("/:id/collections", s.requirePermission("manage_users", s.updateRoleCollections))
			roles.GET("/:id/members", s.requirePermission("manage_users", s.getRoleMembers))
		}

		// 用户管理
		users := api.Group("/users")
		{
			users.GET("", s.requirePermission("manage_users", s.getUsers))
			users.GET("/:id", s.requirePermission("manage_users", s.getUser))
			users.PUT("/:id", s.requirePermission("manage_users", s.updateUser))
			users.PUT("/:id/collections", s.requirePermission("manage_users", s.updateUserCollections))
			users.POST("/:id/subscription", s.requirePermission("generate_subscriptions", s.generateSubscription))
			users.POST("/set-first-admin", s.setFirstUserAsAdmin)
		}

		// 通知渠道管理
		notifications := api.Group("/notifications")
		{
			notifications.GET("", s.requirePermission("manage_providers", s.getNotificationChannels))
			notifications.POST("", s.requirePermission("manage_providers", s.createNotificationChannel))
			notifications.GET("/:id", s.requirePermission("manage_providers", s.getNotificationChannel))
			notifications.PUT("/:id", s.requirePermission("manage_providers", s.updateNotificationChannel))
			notifications.DELETE("/:id", s.requirePermission("manage_providers", s.deleteNotificationChannel))
			notifications.POST("/:id/test", s.requirePermission("manage_providers", s.testNotificationChannel))
		}

		// 订阅令牌管理
		tokens := api.Group("/tokens")
		{
			tokens.GET("", s.getUserTokens)
			tokens.DELETE("/:token", s.revokeToken)
		}

		// 审计日志管理
		audit := api.Group("/audit")
		{
			audit.GET("/logs", s.requirePermission("view_audit_logs", s.getAuditLogs))
			audit.GET("/access-logs", s.requirePermission("view_audit_logs", s.getAccessLogs))
			audit.GET("/stats", s.requirePermission("view_audit_logs", s.getAuditStats))
			audit.GET("/weekly-clients", s.requirePermission("view_audit_logs", s.getWeeklyClientStats))
		}

		// Azure AD同步管理
		azure := api.Group("/azure")
		{
			azure.POST("/sync", s.requirePermission("manage_users", s.syncAzureUsers))
			azure.GET("/status", s.requirePermission("manage_users", s.getAzureSyncStatus))
		}
	}

	// 订阅导出路由（匿名访问）
	s.router.GET("/sub/:token", s.exportSubscription)

	// 主页路由
	s.router.GET("/", s.index)
	s.router.GET("/login", s.loginPage)
	s.router.GET("/test", s.testPage)
}

// Start 启动服务器
func (s *Server) Start() error {
	logrus.Infof("启动服务器，监听地址: %s", s.config.Listen.HTTP)

	server := &http.Server{
		Addr:    s.config.Listen.HTTP,
		Handler: s.router,
	}

	// 启动清理任务
	go s.startCleanupTasks()

	return server.ListenAndServe()
}

// requirePermission 权限检查中间件
func (s *Server) requirePermission(permission string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户
		session, exists := s.oidcManager.GetCurrentUser(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Code:    401,
				Message: "未认证",
			})
			c.Abort()
			return
		}

		// 检查权限
		if !s.userManager.HasPermission(session.UPN, permission) {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Code:    403,
				Message: "权限不足",
			})
			c.Abort()
			return
		}

		// 调用原始处理器
		handler(c)
	}
}

// startCleanupTasks 启动清理任务
func (s *Server) startCleanupTasks() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 清理过期令牌
			if err := s.tokenManager.CleanupExpiredTokens(); err != nil {
				logrus.Errorf("清理过期令牌失败: %v", err)
			}

			// 保存节点快照
			if err := s.nodeManager.SaveSnapshot(); err != nil {
				logrus.Errorf("保存节点快照失败: %v", err)
			}
		}
	}
}

// index 主页
func (s *Server) index(c *gin.Context) {
	// 从Cookie获取令牌
	token, err := c.Cookie(s.config.Auth.Session.CookieName)
	if err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// 验证令牌
	session, err := s.oidcManager.ValidateSessionToken(token)
	if err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// 获取用户权限
	permissions := s.userManager.GetUserPermissions(session.UPN)
	isAdmin := s.userManager.IsAdmin(session.UPN)

	// 使用模块化的基础模板
	c.HTML(http.StatusOK, "base.html", gin.H{
		"user":        session,
		"permissions": permissions,
		"isAdmin":     isAdmin,
	})
}

// loginPage 登录页面
func (s *Server) loginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

// testPage 测试页面
func (s *Server) testPage(c *gin.Context) {
	c.HTML(http.StatusOK, "test_modular.html", gin.H{})
}

// getCurrentUser 获取当前用户信息
func (s *Server) getCurrentUser(c *gin.Context) {
	session, exists := s.oidcManager.GetCurrentUser(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Code:    401,
			Message: "未认证",
		})
		return
	}

	// 获取用户详细信息
	user, exists := s.userManager.GetUser(session.UPN)
	if !exists {
		// 尝试通过Subject查找现有用户（向后兼容）
		user, exists = s.userManager.GetUserBySubject(session.UserID)
		if exists {
			// 更新现有用户的Subject和角色信息
			user.Subject = session.UserID
			user.Roles = session.Roles
			user.UpdatedAt = time.Now()

			// 保存更新后的用户信息
			if err := s.userManager.SaveUser(user); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{
					Code:    500,
					Message: fmt.Sprintf("更新用户失败: %v", err),
				})
				return
			}
		} else {
			// 创建新用户
			var err error
			user, err = s.userManager.CreateOrUpdateUser(
				session.UserID,
				session.UPN,
				session.DisplayName,
				session.Roles,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{
					Code:    500,
					Message: fmt.Sprintf("创建用户失败: %v", err),
				})
				return
			}
		}
	}

	// 获取用户权限
	permissions := s.userManager.GetUserPermissions(user.UPN)
	isAdmin := s.userManager.IsAdmin(user.UPN)

	// 构建响应数据
	responseData := map[string]interface{}{
		"subject":      user.Subject,
		"upn":          user.UPN,
		"display_name": user.DisplayName,
		"collections":  user.Collections,
		"roles":        user.Roles,
		"disabled":     user.Disabled,
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
		"permissions":  permissions,
		"is_admin":     isAdmin,
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    responseData,
	})
}

// 订阅源管理API

func (s *Server) getProviders(c *gin.Context) {
	providers := s.providerManager.GetProviders()
	SuccessResponse(c, providers)
}

func (s *Server) createProvider(c *gin.Context) {
	var provider models.Provider
	if err := c.ShouldBindJSON(&provider); err != nil {
		ValidationErrorResponse(c, err)
		return
	}

	if err := s.providerManager.AddProvider(&provider); err != nil {
		InternalErrorResponse(c, "创建订阅源", err)
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "create", "provider", provider.ID,
		fmt.Sprintf("创建订阅源: %s (%s)", provider.Name, provider.URL),
		c.ClientIP(), c.GetHeader("User-Agent"))

	SuccessResponse(c, provider)
}

func (s *Server) getProvider(c *gin.Context) {
	id := c.Param("id")
	provider, exists := s.providerManager.GetProvider(id)
	if !exists {
		NotFoundResponse(c, "订阅源")
		return
	}

	SuccessResponse(c, provider)
}

func (s *Server) updateProvider(c *gin.Context) {
	id := c.Param("id")
	var provider models.Provider
	if err := c.ShouldBindJSON(&provider); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.providerManager.UpdateProvider(id, &provider); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新订阅源失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) deleteProvider(c *gin.Context) {
	id := c.Param("id")

	// 获取订阅源信息用于审计日志
	provider, exists := s.providerManager.GetProvider(id)
	if !exists {
		NotFoundResponse(c, "订阅源")
		return
	}

	if err := s.providerManager.DeleteProvider(id); err != nil {
		InternalErrorResponse(c, "删除订阅源", err)
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "delete", "provider", id,
		fmt.Sprintf("删除订阅源: %s (%s)", provider.Name, provider.URL),
		c.ClientIP(), c.GetHeader("User-Agent"))

	SuccessResponse(c, nil)
}

func (s *Server) refreshProvider(c *gin.Context) {
	id := c.Param("id")
	if err := s.providerManager.FetchProvider(id); err != nil {
		InternalErrorResponse(c, "抓取订阅源", err)
		return
	}

	SuccessResponse(c, nil)
}

func (s *Server) disableProvider(c *gin.Context) {
	id := c.Param("id")
	if err := s.providerManager.DisableProvider(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("禁用订阅源失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "disable", "provider", id,
		fmt.Sprintf("禁用订阅源: %s", id),
		c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "禁用成功",
	})
}

func (s *Server) enableProvider(c *gin.Context) {
	id := c.Param("id")
	if err := s.providerManager.EnableProvider(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("启用订阅源失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "enable", "provider", id,
		fmt.Sprintf("启用订阅源: %s", id),
		c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "启用成功",
	})
}

// 节点管理API

func (s *Server) getNodes(c *gin.Context) {
	var filter models.NodeFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	nodes := s.nodeManager.FilterNodes(&filter)
	SuccessResponse(c, nodes)
}

func (s *Server) createNode(c *gin.Context) {
	var req struct {
		Name     string            `json:"name" binding:"required"`
		Protocol string            `json:"protocol" binding:"required"`
		Host     string            `json:"host" binding:"required"`
		Port     int               `json:"port" binding:"required"`
		Country  string            `json:"country"`
		Remark   string            `json:"remark"`
		Params   map[string]string `json:"params"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 创建节点对象
	node := &models.Node{
		Fingerprint: generateNodeID(),
		Name:        req.Name,
		Protocol:    req.Protocol,
		Host:        req.Host,
		Port:        req.Port,
		GeoCountry:  req.Country,
		Params:      req.Params,
		ProviderID:  "manual", // 标记为手动添加
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// 添加到节点管理器
	err := s.nodeManager.UpsertNode(node)
	if err != nil {
		InternalErrorResponse(c, "添加节点", err)
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	userID := "system"
	if session != nil {
		userID = session.UserID
	}
	s.auditManager.LogAudit(userID, "create_node", "node", node.Fingerprint, fmt.Sprintf("手动添加节点: %s (%s://%s:%d)", node.Name, node.Protocol, node.Host, node.Port), c.ClientIP(), c.GetHeader("User-Agent"))

	SuccessResponse(c, node)
}

// generateNodeID 生成节点ID
func generateNodeID() string {
	return fmt.Sprintf("manual_%d", time.Now().UnixNano())
}

func (s *Server) getNodeStats(c *gin.Context) {
	stats := s.nodeManager.GetStats()
	SuccessResponse(c, stats)
}

func (s *Server) getCountries(c *gin.Context) {
	countries := s.nodeManager.GetCountries()
	SuccessResponse(c, countries)
}

func (s *Server) getCities(c *gin.Context) {
	country := c.Query("country")
	if country == "" {
		ErrorResponse(c, http.StatusBadRequest, "缺少国家参数")
		return
	}

	cities := s.nodeManager.GetCities(country)
	SuccessResponse(c, cities)
}

func (s *Server) getNode(c *gin.Context) {
	id := c.Param("id")
	node, exists := s.nodeManager.GetNode(id)
	if !exists {
		NotFoundResponse(c, "节点")
		return
	}

	SuccessResponse(c, node)
}

func (s *Server) updateNode(c *gin.Context) {
	id := c.Param("id")

	// 检查节点是否存在
	node, exists := s.nodeManager.GetNode(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "节点不存在",
		})
		return
	}

	// 只允许修改手动添加的节点
	if node.ProviderID != "manual" {
		c.JSON(http.StatusForbidden, models.APIResponse{
			Code:    403,
			Message: "只能修改手动添加的节点",
		})
		return
	}

	var req struct {
		Name     string            `json:"name" binding:"required"`
		Protocol string            `json:"protocol" binding:"required"`
		Host     string            `json:"host" binding:"required"`
		Port     int               `json:"port" binding:"required"`
		Country  string            `json:"country"`
		Remark   string            `json:"remark"`
		Params   map[string]string `json:"params"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 更新节点信息
	node.Name = req.Name
	node.Protocol = req.Protocol
	node.Host = req.Host
	node.Port = req.Port
	node.GeoCountry = req.Country
	node.Params = req.Params
	node.UpdatedAt = time.Now()

	// 保存更新后的节点
	err := s.nodeManager.UpsertNode(node)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新节点失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	userID := "system"
	if session != nil {
		userID = session.UserID
	}
	s.auditManager.LogAudit(userID, "update_node", "node", node.Fingerprint,
		fmt.Sprintf("修改手动节点: %s (%s://%s:%d)", node.Name, node.Protocol, node.Host, node.Port),
		c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "节点更新成功",
		Data:    node,
	})
}

func (s *Server) deleteNode(c *gin.Context) {
	id := c.Param("id")

	// 检查节点是否存在
	node, exists := s.nodeManager.GetNode(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "节点不存在",
		})
		return
	}

	// 只允许删除手动添加的节点
	if node.ProviderID != "manual" {
		c.JSON(http.StatusForbidden, models.APIResponse{
			Code:    403,
			Message: "只能删除手动添加的节点",
		})
		return
	}

	// 删除节点
	err := s.nodeManager.DeleteNode(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("删除节点失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	userID := "system"
	if session != nil {
		userID = session.UserID
	}
	s.auditManager.LogAudit(userID, "delete_node", "node", id,
		fmt.Sprintf("删除手动节点: %s (%s://%s:%d)", node.Name, node.Protocol, node.Host, node.Port),
		c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "节点删除成功",
	})
}

func (s *Server) batchAddNodesToCollection(c *gin.Context) {
	var req struct {
		CollectionID string   `json:"collection_id" binding:"required"`
		NodeFPs      []string `json:"node_fps" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 检查集合是否存在
	_, exists := s.collectionManager.GetCollection(req.CollectionID)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "集合不存在",
		})
		return
	}

	// 批量添加节点到集合
	err := s.collectionManager.AddNodesToCollection(req.CollectionID, req.NodeFPs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("添加节点到集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: fmt.Sprintf("成功添加 %d 个节点到集合", len(req.NodeFPs)),
		Data: map[string]interface{}{
			"added_count": len(req.NodeFPs),
			"total_count": len(req.NodeFPs),
		},
	})
}

// 集合管理API

func (s *Server) getCollections(c *gin.Context) {
	collections := s.collectionManager.GetCollections()
	SuccessResponse(c, collections)
}

func (s *Server) createCollection(c *gin.Context) {
	var req struct {
		Name string      `json:"name" binding:"required"`
		Tags interface{} `json:"tags"` // 使用interface{}来灵活处理字符串或数组
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 处理标签字段，支持字符串和数组两种格式
	var tags []string
	if req.Tags != nil {
		switch v := req.Tags.(type) {
		case string:
			if v != "" {
				// 按逗号分割字符串
				for _, tag := range strings.Split(v, ",") {
					if trimmed := strings.TrimSpace(tag); trimmed != "" {
						tags = append(tags, trimmed)
					}
				}
			}
		case []interface{}:
			// 处理数组格式
			for _, item := range v {
				if str, ok := item.(string); ok && str != "" {
					if trimmed := strings.TrimSpace(str); trimmed != "" {
						tags = append(tags, trimmed)
					}
				}
			}
		case []string:
			// 直接是字符串数组
			for _, tag := range v {
				if trimmed := strings.TrimSpace(tag); trimmed != "" {
					tags = append(tags, trimmed)
				}
			}
		}
	}

	collection, err := s.collectionManager.CreateCollection(req.Name, tags)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("创建集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "创建成功",
		Data:    collection,
	})
}

func (s *Server) getCollection(c *gin.Context) {
	id := c.Param("id")
	collection, exists := s.collectionManager.GetCollection(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "集合不存在",
		})
		return
	}

	SuccessResponse(c, collection)
}

func (s *Server) updateCollection(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name string   `json:"name" binding:"required"`
		Tags []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.collectionManager.UpdateCollection(id, req.Name, req.Tags); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) deleteCollection(c *gin.Context) {
	id := c.Param("id")
	if err := s.collectionManager.DeleteCollection(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("删除集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "删除成功",
	})
}

func (s *Server) addNodesToCollection(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		NodeFPs []string `json:"node_fps" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.collectionManager.AddNodesToCollection(id, req.NodeFPs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("添加节点到集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "添加成功",
	})
}

func (s *Server) removeNodesFromCollection(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		NodeFPs []string `json:"node_fps" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.collectionManager.RemoveNodesFromCollection(id, req.NodeFPs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("从集合中移除节点失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "移除成功",
	})
}

func (s *Server) sortCollectionNodes(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		SortedFPs []string `json:"sorted_fps" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.collectionManager.SortNodesInCollection(id, req.SortedFPs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("排序集合节点失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "排序成功",
	})
}

// 角色管理API

func (s *Server) getRoles(c *gin.Context) {
	roles := s.userManager.GetRoles()
	SuccessResponse(c, roles)
}

func (s *Server) createRole(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Collections []string `json:"collections"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	role, err := s.userManager.CreateRole(req.Name, req.Collections)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("创建角色失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "创建成功",
		Data:    role,
	})
}

func (s *Server) getRole(c *gin.Context) {
	id := c.Param("id")
	role, exists := s.userManager.GetRole(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "角色不存在",
		})
		return
	}

	SuccessResponse(c, role)
}

func (s *Server) updateRole(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Collections []string `json:"collections"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.userManager.UpdateRole(id, req.Name, req.Collections, req.Permissions); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新角色失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) deleteRole(c *gin.Context) {
	id := c.Param("id")
	if err := s.userManager.DeleteRole(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("删除角色失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "删除成功",
	})
}

func (s *Server) updateRoleCollections(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Collections []string `json:"collections" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	if err := s.userManager.UpdateRole(id, "", req.Collections, nil); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新角色集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) getRoleMembers(c *gin.Context) {
	roleID := c.Param("id")

	// 获取所有用户
	users := s.userManager.GetUsers()
	var members []*models.User

	// 筛选属于该角色的用户
	for _, user := range users {
		for _, role := range user.Roles {
			if role == roleID {
				members = append(members, user)
				break
			}
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    members,
	})
}

// 用户管理API

func (s *Server) getUsers(c *gin.Context) {
	users := s.userManager.GetUsers()
	SuccessResponse(c, users)
}

func (s *Server) getUser(c *gin.Context) {
	id := c.Param("id")

	// 首先尝试通过UPN查找用户
	user, exists := s.userManager.GetUser(id)
	if !exists {
		// 如果UPN查找失败，尝试通过Subject查找（向后兼容）
		user, exists = s.userManager.GetUserBySubject(id)
	}

	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "用户不存在",
		})
		return
	}

	SuccessResponse(c, user)
}

func (s *Server) updateUserCollections(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Collections []string `json:"collections"` // 移除 binding:"required"，允许空数组
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 首先尝试通过UPN查找用户
	user, exists := s.userManager.GetUser(id)
	if !exists {
		// 如果UPN查找失败，尝试通过Subject查找（向后兼容）
		user, exists = s.userManager.GetUserBySubject(id)
	}

	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "用户不存在",
		})
		return
	}

	if err := s.userManager.SetUserCollections(user.UPN, req.Collections); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新用户集合失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) generateSubscription(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		RPM        int    `json:"rpm"`
		ValidDays  int    `json:"valid_days"`
		ClientName string `json:"client_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 设置默认值
	if req.RPM <= 0 {
		req.RPM = s.config.Limits.DefaultRPM
	}
	if req.ValidDays <= 0 {
		req.ValidDays = 365 // 默认1年
	}

	token, err := s.tokenManager.GenerateToken(id, req.RPM, req.ValidDays, req.ClientName, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("生成订阅令牌失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "create", "subscription", token.TokenHash,
		fmt.Sprintf("为用户 %s 生成订阅令牌，客户端: %s, RPM: %d, 有效期: %d天", id, req.ClientName, req.RPM, req.ValidDays),
		c.ClientIP(), c.GetHeader("User-Agent"))

	// 生成订阅链接（不包含target参数，由用户选择）
	baseURL := s.config.Server.BaseURL
	subscriptionURL := fmt.Sprintf("%s/sub/%s", baseURL, token.Token)

	// 返回包含订阅链接的响应
	response := map[string]interface{}{
		"token":            token.Token,
		"token_hash":       token.TokenHash,
		"subscription_url": subscriptionURL,
		"client_name":      req.ClientName,
		"rpm":              req.RPM,
		"valid_days":       req.ValidDays,
		"valid_to":         token.ValidTo,
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "生成成功",
		Data:    response,
	})
}

// 订阅令牌管理API

func (s *Server) getUserTokens(c *gin.Context) {
	session, exists := s.oidcManager.GetCurrentUser(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Code:    401,
			Message: "未认证",
		})
		return
	}

	// 生成基础URL
	baseURL := s.config.Server.BaseURL
	tokens := s.tokenManager.GetUserTokensWithURLs(session.UserID, baseURL)
	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    tokens,
	})
}

func (s *Server) revokeToken(c *gin.Context) {
	tokenHash := c.Param("token")

	// 获取令牌信息用于审计日志
	token, exists := s.tokenManager.GetTokenByHash(tokenHash)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "令牌不存在",
		})
		return
	}

	if err := s.tokenManager.RevokeTokenByHash(tokenHash); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("吊销令牌失败: %v", err),
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "delete", "subscription", tokenHash,
		fmt.Sprintf("吊销用户 %s 的订阅令牌", token.UID),
		c.ClientIP(), c.GetHeader("User-Agent"))

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "吊销成功",
	})
}

// 订阅导出API

func (s *Server) exportSubscription(c *gin.Context) {
	token := c.Param("token")
	target := c.DefaultQuery("target", "clash")
	watermark := c.DefaultQuery("watermark", "false") == "true"

	// 获取客户端信息
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// 验证令牌
	subscriptionToken, err := s.tokenManager.ValidateToken(token)
	if err != nil {
		// 记录失败的访问（使用空字符串作为tokenHash，因为令牌无效）
		s.logAccess("", target, clientIP, userAgent, 401, 0)

		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Code:    401,
			Message: "无效的订阅令牌",
		})
		return
	}

	// 导出订阅
	var content []byte
	var etag string

	if target == "auto" {
		// 自动判断客户端需要传递User-Agent
		var err error
		content, etag, err = s.exporter.ExportSubscriptionWithUA(
			subscriptionToken.TokenHash,
			target,
			watermark,
			subscriptionToken.UID,
			userAgent,
		)
		if err != nil {
			// 记录失败的访问
			s.logAccess(subscriptionToken.TokenHash, target, clientIP, userAgent, 500, 0)

			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    500,
				Message: fmt.Sprintf("导出订阅失败: %v", err),
			})
			return
		}
	} else {
		var err error
		content, etag, err = s.exporter.ExportSubscription(
			subscriptionToken.TokenHash,
			target,
			watermark,
			subscriptionToken.UID,
		)
		if err != nil {
			// 记录失败的访问
			s.logAccess(subscriptionToken.TokenHash, target, clientIP, userAgent, 500, 0)

			c.JSON(http.StatusInternalServerError, models.APIResponse{
				Code:    500,
				Message: fmt.Sprintf("导出订阅失败: %v", err),
			})
			return
		}
	}

	// 设置响应头
	c.Header("ETag", etag)
	c.Header("Cache-Control", "public, max-age=300") // 5分钟缓存

	// 检查If-None-Match
	if ifNoneMatch := c.GetHeader("If-None-Match"); ifNoneMatch == etag {
		// 记录304响应
		s.logAccess(subscriptionToken.TokenHash, target, clientIP, userAgent, 304, 0)
		c.Status(http.StatusNotModified)
		return
	}

	// 设置内容类型
	switch target {
	case "clash", "clashr":
		c.Header("Content-Type", "application/x-yaml")
	case "surge4", "surge5", "surge3", "surge2", "surfboard", "loon":
		c.Header("Content-Type", "text/plain")
	case "singbox", "sip008", "v2ray", "mellow":
		c.Header("Content-Type", "application/json")
	case "quantumult", "quantumultx":
		c.Header("Content-Type", "text/plain")
	case "trojan", "ssr", "mixed", "sip002", "shadowsocksd", "auto":
		c.Header("Content-Type", "text/plain")
	default:
		c.Header("Content-Type", "text/plain")
	}

	// 记录成功的访问
	s.logAccess(subscriptionToken.TokenHash, target, clientIP, userAgent, 200, len(content))

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), content)
}

// logAccess 记录访问日志
func (s *Server) logAccess(tokenHash, target, ip, userAgent string, status, size int) {
	// 记录到审计管理器
	if err := s.auditManager.LogAccess(tokenHash, target, ip, userAgent, status, size); err != nil {
		logrus.Errorf("记录访问日志失败: %v", err)
	}

	// 同时记录到应用日志
	logrus.WithFields(logrus.Fields{
		"token_hash": tokenHash,
		"target":     target,
		"ip":         ip,
		"user_agent": userAgent,
		"status":     status,
		"size":       size,
		"timestamp":  time.Now(),
	}).Info("订阅访问日志")
}

// logAudit 记录审计日志
func (s *Server) logAudit(userID, action, resource, resourceID, details, ip, userAgent string) {
	// 记录到审计管理器
	if err := s.auditManager.LogAudit(userID, action, resource, resourceID, details, ip, userAgent); err != nil {
		logrus.Errorf("记录审计日志失败: %v", err)
	}

	// 同时记录到应用日志
	logrus.WithFields(logrus.Fields{
		"user_id":     userID,
		"action":      action,
		"resource":    resource,
		"resource_id": resourceID,
		"details":     details,
		"ip":          ip,
		"user_agent":  userAgent,
		"timestamp":   time.Now(),
	}).Info("操作审计日志")
}

// 审计日志API

func (s *Server) getAuditLogs(c *gin.Context) {
	// 解析查询参数
	var startTime, endTime time.Time
	var userID, action string

	if startStr := c.Query("start_time"); startStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", startStr); err == nil {
			startTime = t
		} else {
			startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
		}
	} else {
		startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
	}

	if endStr := c.Query("end_time"); endStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", endStr); err == nil {
			endTime = t
		} else {
			endTime = time.Now()
		}
	} else {
		endTime = time.Now()
	}

	userID = c.Query("user_id")
	action = c.Query("action")

	// 获取审计日志
	logs, err := s.auditManager.GetAuditLogs(startTime, endTime, userID, action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取审计日志失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    logs,
	})
}

func (s *Server) getAccessLogs(c *gin.Context) {
	// 解析查询参数
	var startTime, endTime time.Time
	var tokenHash, target string

	if startStr := c.Query("start_time"); startStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", startStr); err == nil {
			startTime = t
		} else {
			startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
		}
	} else {
		startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
	}

	if endStr := c.Query("end_time"); endStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", endStr); err == nil {
			endTime = t
		} else {
			endTime = time.Now()
		}
	} else {
		endTime = time.Now()
	}

	tokenHash = c.Query("token_hash")
	target = c.Query("target")

	// 获取访问日志
	logs, err := s.auditManager.GetAccessLogs(startTime, endTime, tokenHash, target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取访问日志失败: %v", err),
		})
		return
	}

	// 增强访问日志，添加用户信息
	enhancedLogs := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		enhancedLog := map[string]interface{}{
			"id":         log.ID,
			"token_hash": log.TokenHash,
			"target":     log.Target,
			"ip":         log.IP,
			"user_agent": log.UserAgent,
			"status":     log.Status,
			"size":       log.Size,
			"timestamp":  log.Timestamp,
		}

		// 尝试通过token_hash获取用户信息
		if token, exists := s.tokenManager.GetTokenByHash(log.TokenHash); exists {
			// 首先尝试通过UPN查找用户
			user, userExists := s.userManager.GetUser(token.UID)
			if !userExists {
				// 如果UPN查找失败，尝试通过Subject查找（向后兼容）
				user, userExists = s.userManager.GetUserBySubject(token.UID)
			}
			if userExists {
				enhancedLog["user_id"] = user.Subject
				enhancedLog["user_name"] = user.DisplayName
				enhancedLog["user_upn"] = user.UPN
			}
		}

		enhancedLogs[i] = enhancedLog
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    enhancedLogs,
	})
}

func (s *Server) getAuditStats(c *gin.Context) {
	// 解析查询参数
	var startTime, endTime time.Time

	if startStr := c.Query("start_time"); startStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", startStr); err == nil {
			startTime = t
		} else {
			startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
		}
	} else {
		startTime = time.Now().AddDate(0, 0, -30) // 默认30天前
	}

	if endStr := c.Query("end_time"); endStr != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", endStr); err == nil {
			endTime = t
		} else {
			endTime = time.Now()
		}
	} else {
		endTime = time.Now()
	}

	// 获取访问统计
	accessStats, err := s.auditManager.GetAccessStats(startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取访问统计失败: %v", err),
		})
		return
	}

	// 获取审计统计
	auditStats, err := s.auditManager.GetAuditStats(startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取审计统计失败: %v", err),
		})
		return
	}

	// 获取用户订阅统计
	userStats := s.getUserSubscriptionStats(startTime, endTime)

	// 合并统计信息
	stats := map[string]interface{}{
		"access_stats": accessStats,
		"audit_stats":  auditStats,
		"user_stats":   userStats,
		"time_range": map[string]interface{}{
			"start_time": startTime,
			"end_time":   endTime,
		},
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    stats,
	})
}

// getWeeklyClientStats 获取一周内客户端统计
func (s *Server) getWeeklyClientStats(c *gin.Context) {
	stats, err := s.auditManager.GetWeeklyClientStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取一周内客户端统计失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    stats,
	})
}

// getUserSubscriptionStats 获取用户订阅统计
func (s *Server) getUserSubscriptionStats(startTime, endTime time.Time) map[string]interface{} {
	// 获取所有访问日志
	logs, err := s.auditManager.GetAccessLogs(startTime, endTime, "", "")
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("获取访问日志失败: %v", err),
		}
	}

	// 统计每个用户的订阅次数
	userStats := make(map[string]map[string]interface{})

	for _, log := range logs {
		// 通过token_hash获取用户信息
		if token, exists := s.tokenManager.GetTokenByHash(log.TokenHash); exists {
			// 首先尝试通过UPN查找用户
			user, userExists := s.userManager.GetUser(token.UID)
			if !userExists {
				// 如果UPN查找失败，尝试通过Subject查找（向后兼容）
				user, userExists = s.userManager.GetUserBySubject(token.UID)
			}
			if userExists {
				userID := user.Subject

				if userStats[userID] == nil {
					userStats[userID] = map[string]interface{}{
						"user_id":       user.Subject,
						"user_name":     user.DisplayName,
						"user_upn":      user.UPN,
						"total_count":   0,
						"success_count": 0,
						"error_count":   0,
						"total_size":    0,
						"last_access":   time.Time{},
						"clients":       make(map[string]int),
						"targets":       make(map[string]int),
					}
				}

				stats := userStats[userID]
				stats["total_count"] = stats["total_count"].(int) + 1
				stats["total_size"] = stats["total_size"].(int) + log.Size

				if log.Status >= 200 && log.Status < 300 {
					stats["success_count"] = stats["success_count"].(int) + 1
				} else {
					stats["error_count"] = stats["error_count"].(int) + 1
				}

				// 更新最后访问时间
				if log.Timestamp.After(stats["last_access"].(time.Time)) {
					stats["last_access"] = log.Timestamp
				}

				// 统计客户端
				clients := stats["clients"].(map[string]int)
				clients[log.UserAgent]++

				// 统计目标格式
				targets := stats["targets"].(map[string]int)
				targets[log.Target]++
			}
		}
	}

	return map[string]interface{}{
		"user_count":   len(userStats),
		"user_details": userStats,
	}
}

// Azure AD同步API

func (s *Server) syncAzureUsers(c *gin.Context) {
	// 检查Azure配置是否启用
	if !s.config.Azure.Enabled {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: "Azure AD同步未启用",
		})
		return
	}

	// 检查是否有配置的用户组
	if len(s.config.Azure.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: "未配置Azure AD用户组",
		})
		return
	}

	// 记录审计日志
	session, _ := s.oidcManager.GetCurrentUser(c)
	s.logAudit(session.UserID, "sync", "azure_users", "",
		"手动触发Azure AD用户同步",
		c.ClientIP(), c.GetHeader("User-Agent"))

	// 执行实际的同步逻辑
	syncedCount := 0
	for _, groupID := range s.config.Azure.GroupIDs {
		// 模拟从Azure AD获取用户
		// 在实际环境中，这里应该调用Azure Graph API
		azureUsers := s.simulateAzureUsers(groupID)

		// 同步用户到本地系统
		for _, azureUser := range azureUsers {
			if err := s.syncUserFromAzure(azureUser); err != nil {
				logrus.Errorf("同步用户失败 %s: %v", azureUser.UserPrincipalName, err)
				continue
			}
			syncedCount++
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: fmt.Sprintf("Azure AD用户同步完成，共同步 %d 个用户", syncedCount),
		Data: map[string]interface{}{
			"group_count":  len(s.config.Azure.GroupIDs),
			"groups":       s.config.Azure.GroupIDs,
			"synced_count": syncedCount,
		},
	})
}

func (s *Server) getAzureSyncStatus(c *gin.Context) {
	status := map[string]interface{}{
		"enabled":       s.config.Azure.Enabled,
		"tenant_id":     s.config.Azure.TenantID,
		"client_id":     s.config.Azure.ClientID,
		"group_count":   len(s.config.Azure.GroupIDs),
		"groups":        s.config.Azure.GroupIDs,
		"sync_interval": s.config.Azure.SyncInterval,
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    status,
	})
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

// simulateAzureUsers 从Azure AD获取用户
func (s *Server) simulateAzureUsers(groupID string) []*AzureUser {
	// 尝试从真实的Azure AD获取用户
	users, err := s.getAzureADUsers(groupID)
	if err != nil {
		logrus.Errorf("从Azure AD获取用户失败: %v", err)
		// 如果获取失败，返回空列表而不是模拟数据
		return []*AzureUser{}
	}
	return users
}

// getAzureADUsers 从Azure AD获取用户组成员
func (s *Server) getAzureADUsers(groupID string) ([]*AzureUser, error) {
	// 获取访问令牌
	token, err := s.getAzureAccessToken()
	if err != nil {
		return nil, fmt.Errorf("获取访问令牌失败: %w", err)
	}

	// 首先尝试通过组ID获取，如果失败则通过组名称搜索
	var actualGroupID string
	if isGUID(groupID) {
		actualGroupID = groupID
	} else {
		// 通过组名称搜索组ID
		actualGroupID, err = s.findGroupIDByName(token, groupID)
		if err != nil {
			return nil, fmt.Errorf("查找组ID失败: %w", err)
		}
	}

	// 获取所有组成员（处理分页）
	return s.getAllGroupMembers(token, actualGroupID, groupID)
}

// getAllGroupMembers 获取所有组成员（处理分页）
func (s *Server) getAllGroupMembers(token, groupID, originalGroupID string) ([]*AzureUser, error) {
	var allUsers []*AzureUser
	nextURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members", groupID)

	for nextURL != "" {
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("创建请求失败: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("API请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		}

		var graphResponse struct {
			Value []struct {
				ID                string `json:"id"`
				UserPrincipalName string `json:"userPrincipalName"`
				DisplayName       string `json:"displayName"`
				GivenName         string `json:"givenName"`
				Surname           string `json:"surname"`
				Mail              string `json:"mail"`
				JobTitle          string `json:"jobTitle"`
				Department        string `json:"department"`
			} `json:"value"`
			ODataNextLink string `json:"@odata.nextLink"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&graphResponse); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("解析响应失败: %w", err)
		}
		resp.Body.Close()

		// 转换当前页的用户
		for _, user := range graphResponse.Value {
			allUsers = append(allUsers, &AzureUser{
				ID:                user.ID,
				UserPrincipalName: user.UserPrincipalName,
				DisplayName:       user.DisplayName,
				GivenName:         user.GivenName,
				Surname:           user.Surname,
				Mail:              user.Mail,
				JobTitle:          user.JobTitle,
				Department:        user.Department,
				Groups:            []string{originalGroupID},
			})
		}

		// 设置下一页URL
		nextURL = graphResponse.ODataNextLink

		// 添加延迟以避免API限制
		if nextURL != "" {
			time.Sleep(100 * time.Millisecond)
		}
	}

	logrus.Infof("从Azure AD组 %s 获取到 %d 个用户", originalGroupID, len(allUsers))
	return allUsers, nil
}

// getAzureAccessToken 获取Azure AD访问令牌
func (s *Server) getAzureAccessToken() (string, error) {
	// 使用客户端凭据流获取访问令牌
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", s.config.Azure.TenantID)

	data := url.Values{}
	data.Set("client_id", s.config.Azure.ClientID)
	data.Set("client_secret", s.config.Azure.ClientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("获取令牌失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("解析令牌响应失败: %w", err)
	}

	return tokenResponse.AccessToken, nil
}

// isGUID 检查字符串是否为GUID格式
func isGUID(s string) bool {
	// 简单的GUID格式检查
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// findGroupIDByName 通过组名称查找组ID
func (s *Server) findGroupIDByName(token, groupName string) (string, error) {
	// 使用Microsoft Graph API搜索组
	// 使用正确的$search格式：displayName:value
	encodedGroupName := url.QueryEscape(groupName)
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups?$search=\"displayName:%s\"&$select=id,displayName", encodedGroupName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("搜索组失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var searchResponse struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
		return "", fmt.Errorf("解析搜索响应失败: %w", err)
	}

	if len(searchResponse.Value) == 0 {
		return "", fmt.Errorf("未找到名为 '%s' 的组", groupName)
	}

	if len(searchResponse.Value) > 1 {
		return "", fmt.Errorf("找到多个名为 '%s' 的组，请使用组ID", groupName)
	}

	return searchResponse.Value[0].ID, nil
}

// syncUserFromAzure 从Azure AD同步单个用户
func (s *Server) syncUserFromAzure(azureUser *AzureUser) error {
	// 检查用户是否已存在
	existingUser, exists := s.userManager.GetUser(azureUser.UserPrincipalName)

	if exists {
		// 保护现有用户的管理员权限
		// 如果用户已经是管理员，保持管理员权限
		// 如果用户是普通用户，保持普通用户权限
		preservedRoles := existingUser.Roles

		// 更新现有用户信息，但保持原有角色
		_, err := s.userManager.CreateOrUpdateUser(
			azureUser.ID,
			azureUser.UserPrincipalName,
			azureUser.DisplayName,
			preservedRoles, // 保持原有角色
		)
		if err != nil {
			return fmt.Errorf("更新用户失败: %w", err)
		}
		logrus.Debugf("更新用户: %s (保持角色: %v)", azureUser.DisplayName, preservedRoles)
	} else {
		// 创建新用户，默认为普通用户
		_, err := s.userManager.CreateOrUpdateUser(
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

// 通知渠道管理API

func (s *Server) getNotificationChannels(c *gin.Context) {
	channels, err := s.notificationManager.GetChannels()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("获取通知渠道失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    channels,
	})
}

func (s *Server) createNotificationChannel(c *gin.Context) {
	var req struct {
		Name       string `json:"name" binding:"required"`
		WebhookURL string `json:"webhook_url" binding:"required"`
		Format     string `json:"format" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 验证格式
	if req.Format != "dingtalk" && req.Format != "lark" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: "不支持的格式，仅支持 dingtalk 和 lark",
		})
		return
	}

	channel, err := s.notificationManager.CreateChannel(req.Name, req.WebhookURL, req.Format)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("创建通知渠道失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "创建成功",
		Data:    channel,
	})
}

func (s *Server) getNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	channel, exists := s.notificationManager.GetChannel(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "通知渠道不存在",
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    channel,
	})
}

func (s *Server) updateNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name       string `json:"name" binding:"required"`
		WebhookURL string `json:"webhook_url" binding:"required"`
		Format     string `json:"format" binding:"required"`
		Enabled    bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 验证格式
	if req.Format != "dingtalk" && req.Format != "lark" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: "不支持的格式，仅支持 dingtalk 和 lark",
		})
		return
	}

	if err := s.notificationManager.UpdateChannel(id, req.Name, req.WebhookURL, req.Format, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新通知渠道失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

func (s *Server) deleteNotificationChannel(c *gin.Context) {
	id := c.Param("id")
	if err := s.notificationManager.DeleteChannel(id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("删除通知渠道失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "删除成功",
	})
}

func (s *Server) testNotificationChannel(c *gin.Context) {
	id := c.Param("id")

	// 获取通知渠道
	channel, exists := s.notificationManager.GetChannel(id)
	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "通知渠道不存在",
		})
		return
	}

	// 发送测试消息
	if err := s.sendTestNotification(channel); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("发送测试通知失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "测试通知发送成功",
	})
}

// sendTestNotification 发送测试通知
func (s *Server) sendTestNotification(channel *models.NotificationChannel) error {
	// 构建测试消息
	message := map[string]interface{}{
		"title":   "测试通知",
		"content": "这是一条测试消息，用于验证通知渠道配置是否正确。",
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	}

	// 根据格式类型构建不同的消息格式
	var payload []byte
	var err error

	switch channel.Format {
	case "dingtalk":
		payload, err = s.buildDingTalkMessage(message)
	case "lark":
		payload, err = s.buildLarkMessage(message)
	default:
		payload, err = s.buildDefaultMessage(message)
	}

	if err != nil {
		return fmt.Errorf("构建消息失败: %w", err)
	}

	// 发送HTTP请求
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(channel.WebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("通知渠道返回错误状态: %d", resp.StatusCode)
	}

	return nil
}

// buildDingTalkMessage 构建钉钉消息格式
func (s *Server) buildDingTalkMessage(message map[string]interface{}) ([]byte, error) {
	dingTalkMsg := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": fmt.Sprintf("%s\n%s\n时间: %s",
				message["title"],
				message["content"],
				message["time"]),
		},
	}
	return json.Marshal(dingTalkMsg)
}

// buildLarkMessage 构建飞书消息格式
func (s *Server) buildLarkMessage(message map[string]interface{}) ([]byte, error) {
	larkMsg := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": fmt.Sprintf("%s\n%s\n时间: %s",
				message["title"],
				message["content"],
				message["time"]),
		},
	}
	return json.Marshal(larkMsg)
}

// buildDefaultMessage 构建默认消息格式
func (s *Server) buildDefaultMessage(message map[string]interface{}) ([]byte, error) {
	return json.Marshal(message)
}

// 更新用户信息（包括角色和禁用状态）
func (s *Server) updateUser(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Roles    []string `json:"roles"`
		Disabled bool     `json:"disabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code:    400,
			Message: fmt.Sprintf("请求参数错误: %v", err),
		})
		return
	}

	// 获取用户信息
	// 首先尝试通过UPN查找用户
	user, exists := s.userManager.GetUser(id)
	if !exists {
		// 如果UPN查找失败，尝试通过Subject查找（向后兼容）
		user, exists = s.userManager.GetUserBySubject(id)
	}

	if !exists {
		c.JSON(http.StatusNotFound, models.APIResponse{
			Code:    404,
			Message: "用户不存在",
		})
		return
	}

	// 更新用户角色
	if req.Roles != nil {
		user.Roles = req.Roles
	}

	// 更新禁用状态
	user.Disabled = req.Disabled
	user.UpdatedAt = time.Now()

	// 保存用户信息
	if err := s.userManager.SaveUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("更新用户失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "更新成功",
	})
}

// setFirstUserAsAdmin 设置第一个用户为管理员
func (s *Server) setFirstUserAsAdmin(c *gin.Context) {
	if err := s.userManager.SetFirstUserAsAdmin(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    500,
			Message: fmt.Sprintf("设置第一个用户为管理员失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "第一个用户已设置为管理员",
	})
}
