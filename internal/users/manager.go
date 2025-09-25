package users

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-distributor/internal/fss"
	"proxy-distributor/internal/models"

	"github.com/sirupsen/logrus"
)

// UserManager 用户管理器
type UserManager struct {
	fss   *fss.FSS
	users map[string]*models.User
	roles map[string]*models.Role
}

// NewUserManager 创建用户管理器
func NewUserManager(fss *fss.FSS) *UserManager {
	um := &UserManager{
		fss:   fss,
		users: make(map[string]*models.User),
		roles: make(map[string]*models.Role),
	}

	// 加载现有数据
	if err := um.loadUsers(); err != nil {
		logrus.Errorf("加载用户数据失败: %v", err)
	}

	if err := um.loadRoles(); err != nil {
		logrus.Errorf("加载角色数据失败: %v", err)
	}

	return um
}

// encodeUPN 编码UPN为文件名安全的字符串
// 取@前的部分，并将.替换为_
func encodeUPN(upn string) string {
	// 找到@的位置
	atIndex := strings.Index(upn, "@")
	if atIndex == -1 {
		// 如果没有@，使用整个字符串
		return strings.ReplaceAll(upn, ".", "_")
	}

	// 取@前的部分
	localPart := upn[:atIndex]
	// 将.替换为_
	return strings.ReplaceAll(localPart, ".", "_")
}

// decodeUPN 解码文件名安全的字符串为UPN
// 注意：这个方法无法完全还原原始UPN，因为@后的域名信息丢失了
// 主要用于检查文件名格式
func decodeUPN(encoded string) (string, error) {
	// 由于我们只保存了@前的部分，无法完全还原
	// 这里只做格式检查，不实际解码
	if strings.Contains(encoded, "@") {
		return "", fmt.Errorf("文件名不应包含@字符")
	}
	return encoded, nil
}

// loadUsers 加载用户数据
func (um *UserManager) loadUsers() error {
	// 确保目录存在
	if err := um.fss.EnsureDir("users"); err != nil {
		return err
	}

	// 列出所有用户文件
	files, err := um.fss.ListFiles("users")
	if err != nil {
		return err
	}

	// 加载每个用户文件
	for _, file := range files {
		if !strings.HasSuffix(file, ".json") {
			continue
		}

		userFile := um.fss.GetPath(fmt.Sprintf("users/%s", file))

		var user models.User
		if err := um.fss.ReadJSON(userFile, &user); err != nil {
			logrus.Errorf("读取用户文件失败: %s, 错误: %v", file, err)
			continue
		}

		// 使用UPN作为键
		um.users[user.UPN] = &user
	}

	return nil
}

// loadRoles 加载角色数据
func (um *UserManager) loadRoles() error {
	rolesFile := um.fss.GetPath("roles.json")

	// 如果文件不存在，创建默认配置
	if !um.fss.FileExists("roles.json") {
		defaultRoles := []*models.Role{
			{
				ID:          "admin",
				Name:        "管理员",
				Collections: []string{},
				Permissions: []string{
					"manage_providers",
					"manage_collections",
					"manage_users",
					"generate_subscriptions",
					"view_audit_logs",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				ID:          "user",
				Name:        "普通用户",
				Collections: []string{},
				Permissions: []string{
					"copy_subscription_links",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}
		if err := um.fss.WriteJSON(rolesFile, defaultRoles); err != nil {
			return fmt.Errorf("创建默认角色配置失败: %w", err)
		}
	}

	// 读取角色配置
	var roles []*models.Role
	if err := um.fss.ReadJSON(rolesFile, &roles); err != nil {
		return fmt.Errorf("读取角色配置失败: %w", err)
	}

	// 加载到内存
	um.roles = make(map[string]*models.Role)
	for _, role := range roles {
		um.roles[role.ID] = role
	}

	return nil
}

// saveRoles 保存角色配置
func (um *UserManager) saveRoles() error {
	rolesFile := um.fss.GetPath("roles.json")

	var roles []*models.Role
	for _, role := range um.roles {
		roles = append(roles, role)
	}

	return um.fss.WriteJSON(rolesFile, roles)
}

// GetUser 获取用户（通过UPN）
func (um *UserManager) GetUser(upn string) (*models.User, bool) {
	user, exists := um.users[upn]
	return user, exists
}

// GetUserBySubject 根据Subject获取用户（向后兼容）
func (um *UserManager) GetUserBySubject(subject string) (*models.User, bool) {
	for _, user := range um.users {
		if user.Subject == subject {
			return user, true
		}
	}
	return nil, false
}

// GetUserByUPN 根据UPN获取用户（保持向后兼容）
func (um *UserManager) GetUserByUPN(upn string) (*models.User, bool) {
	return um.GetUser(upn)
}

// CreateOrUpdateUser 创建或更新用户
func (um *UserManager) CreateOrUpdateUser(subject, upn, displayName string, roles []string) (*models.User, error) {
	user, exists := um.users[upn]
	if !exists {
		// 检查是否为系统内第一个用户
		isFirstUser := len(um.users) == 0

		// 如果是第一个用户，自动分配管理员角色
		if isFirstUser {
			roles = []string{"admin"}
			logrus.Infof("检测到系统内第一个用户 %s (%s)，自动分配管理员角色", displayName, upn)
		}

		user = &models.User{
			Subject:     subject,
			UPN:         upn,
			DisplayName: displayName,
			Collections: []string{},
			Roles:       roles,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	} else {
		user.UPN = upn
		user.DisplayName = displayName
		user.Roles = roles
		user.UpdatedAt = time.Now()
	}

	// 保存到文件
	encodedUPN := encodeUPN(upn)
	userFile := um.fss.GetPath(fmt.Sprintf("users/%s.json", encodedUPN))
	if err := um.fss.WriteJSON(userFile, user); err != nil {
		return nil, err
	}

	// 更新内存
	um.users[upn] = user

	return user, nil
}

// SetFirstUserAsAdmin 将系统内第一个用户设置为管理员
func (um *UserManager) SetFirstUserAsAdmin() error {
	if len(um.users) == 0 {
		return fmt.Errorf("系统中没有用户")
	}

	// 找到创建时间最早的用户
	var firstUser *models.User
	var earliestTime time.Time

	for _, user := range um.users {
		if firstUser == nil || user.CreatedAt.Before(earliestTime) {
			firstUser = user
			earliestTime = user.CreatedAt
		}
	}

	if firstUser == nil {
		return fmt.Errorf("未找到第一个用户")
	}

	// 检查是否已经是管理员
	hasAdminRole := false
	for _, role := range firstUser.Roles {
		if role == "admin" {
			hasAdminRole = true
			break
		}
	}

	if !hasAdminRole {
		// 添加管理员角色
		firstUser.Roles = append(firstUser.Roles, "admin")
		firstUser.UpdatedAt = time.Now()

		// 保存用户信息
		if err := um.SaveUser(firstUser); err != nil {
			return fmt.Errorf("保存用户信息失败: %w", err)
		}

		logrus.Infof("已将第一个用户 %s (%s) 设置为管理员", firstUser.DisplayName, firstUser.UPN)
	} else {
		logrus.Infof("第一个用户 %s (%s) 已经是管理员", firstUser.DisplayName, firstUser.UPN)
	}

	return nil
}

// GetUsers 获取所有用户
func (um *UserManager) GetUsers() []*models.User {
	var users []*models.User
	for _, user := range um.users {
		users = append(users, user)
	}
	return users
}

// AddUserCollections 添加用户个人集合
func (um *UserManager) AddUserCollections(upn string, collections []string) error {
	user, exists := um.users[upn]
	if !exists {
		return fmt.Errorf("用户不存在: %s", upn)
	}

	// 去重并添加新集合
	existingCollections := make(map[string]bool)
	for _, collection := range user.Collections {
		existingCollections[collection] = true
	}

	for _, collection := range collections {
		if !existingCollections[collection] {
			user.Collections = append(user.Collections, collection)
		}
	}

	user.UpdatedAt = time.Now()

	// 保存到文件
	encodedUPN := encodeUPN(upn)
	userFile := um.fss.GetPath(fmt.Sprintf("users/%s.json", encodedUPN))
	return um.fss.WriteJSON(userFile, user)
}

// SetUserCollections 设置用户个人集合（完全替换）
func (um *UserManager) SetUserCollections(upn string, collections []string) error {
	user, exists := um.users[upn]
	if !exists {
		return fmt.Errorf("用户不存在: %s", upn)
	}

	// 直接替换集合列表
	user.Collections = collections
	user.UpdatedAt = time.Now()

	// 保存到文件
	encodedUPN := encodeUPN(upn)
	userFile := um.fss.GetPath(fmt.Sprintf("users/%s.json", encodedUPN))
	return um.fss.WriteJSON(userFile, user)
}

// RemoveUserCollections 移除用户个人集合
func (um *UserManager) RemoveUserCollections(upn string, collections []string) error {
	user, exists := um.users[upn]
	if !exists {
		return fmt.Errorf("用户不存在: %s", upn)
	}

	// 移除集合
	removeCollections := make(map[string]bool)
	for _, collection := range collections {
		removeCollections[collection] = true
	}

	var newCollections []string
	for _, collection := range user.Collections {
		if !removeCollections[collection] {
			newCollections = append(newCollections, collection)
		}
	}

	user.Collections = newCollections
	user.UpdatedAt = time.Now()

	// 保存到文件
	encodedUPN := encodeUPN(upn)
	userFile := um.fss.GetPath(fmt.Sprintf("users/%s.json", encodedUPN))
	return um.fss.WriteJSON(userFile, user)
}

// GetUserCollections 获取用户的所有集合（角色集合 + 个人集合）
func (um *UserManager) GetUserCollections(upn string) []string {
	user, exists := um.users[upn]
	if !exists {
		return []string{}
	}

	// 获取角色集合
	roleCollections := um.getRoleCollections(user.Roles)

	// 合并个人集合
	allCollections := make(map[string]bool)
	for _, collection := range roleCollections {
		allCollections[collection] = true
	}
	for _, collection := range user.Collections {
		allCollections[collection] = true
	}

	// 转换为切片
	var result []string
	for collection := range allCollections {
		result = append(result, collection)
	}

	return result
}

// getRoleCollections 获取角色绑定的集合
func (um *UserManager) getRoleCollections(roles []string) []string {
	var collections []string
	for _, roleID := range roles {
		if role, exists := um.roles[roleID]; exists {
			collections = append(collections, role.Collections...)
		}
	}
	return collections
}

// GetUserPermissions 获取用户权限
func (um *UserManager) GetUserPermissions(upn string) []string {
	user, exists := um.users[upn]
	if !exists {
		return []string{}
	}

	var permissions []string
	for _, roleID := range user.Roles {
		if role, exists := um.roles[roleID]; exists {
			permissions = append(permissions, role.Permissions...)
		}
	}

	// 去重
	permissionMap := make(map[string]bool)
	var uniquePermissions []string
	for _, permission := range permissions {
		if !permissionMap[permission] {
			permissionMap[permission] = true
			uniquePermissions = append(uniquePermissions, permission)
		}
	}

	return uniquePermissions
}

// HasPermission 检查用户是否有指定权限
func (um *UserManager) HasPermission(upn string, permission string) bool {
	permissions := um.GetUserPermissions(upn)
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// IsAdmin 检查用户是否为管理员
func (um *UserManager) IsAdmin(upn string) bool {
	return um.HasPermission(upn, "manage_providers") ||
		um.HasPermission(upn, "manage_collections") ||
		um.HasPermission(upn, "manage_users")
}

// GetRoles 获取所有角色
func (um *UserManager) GetRoles() []*models.Role {
	var roles []*models.Role
	for _, role := range um.roles {
		roles = append(roles, role)
	}
	return roles
}

// GetRole 获取指定角色
func (um *UserManager) GetRole(id string) (*models.Role, bool) {
	role, exists := um.roles[id]
	return role, exists
}

// CreateRole 创建角色
func (um *UserManager) CreateRole(name string, collections []string) (*models.Role, error) {
	role := &models.Role{
		ID:          fmt.Sprintf("role_%d", time.Now().Unix()),
		Name:        name,
		Collections: collections,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// 保存到文件
	um.roles[role.ID] = role
	if err := um.saveRoles(); err != nil {
		return nil, err
	}

	return role, nil
}

// UpdateRole 更新角色
func (um *UserManager) UpdateRole(id string, name string, collections []string, permissions []string) error {
	role, exists := um.roles[id]
	if !exists {
		return fmt.Errorf("角色不存在: %s", id)
	}

	if name != "" {
		role.Name = name
	}
	if collections != nil {
		role.Collections = collections
	}
	if permissions != nil {
		role.Permissions = permissions
	}
	role.UpdatedAt = time.Now()

	// 保存到文件
	return um.saveRoles()
}

// DeleteRole 删除角色
func (um *UserManager) DeleteRole(id string) error {
	if _, exists := um.roles[id]; !exists {
		return fmt.Errorf("角色不存在: %s", id)
	}

	delete(um.roles, id)

	// 保存到文件
	return um.saveRoles()
}

// GetUserStats 获取用户统计信息
func (um *UserManager) GetUserStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_users": len(um.users),
		"total_roles": len(um.roles),
	}

	// 统计角色分布
	roleCounts := make(map[string]int)
	for _, user := range um.users {
		for _, role := range user.Roles {
			roleCounts[role]++
		}
	}
	stats["role_distribution"] = roleCounts

	// 统计个人集合数量分布
	collectionCounts := make(map[int]int)
	for _, user := range um.users {
		count := len(user.Collections)
		collectionCounts[count]++
	}
	stats["personal_collection_counts"] = collectionCounts

	return stats
}

// SaveUser 保存用户信息
func (um *UserManager) SaveUser(user *models.User) error {
	// 更新内存中的用户信息
	um.users[user.UPN] = user

	// 保存到文件
	return um.saveUser(user)
}

// saveUser 保存单个用户到文件
func (um *UserManager) saveUser(user *models.User) error {
	// 序列化用户数据
	data, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户数据失败: %w", err)
	}

	// 保存到文件，使用UPN作为文件名
	encodedUPN := encodeUPN(user.UPN)
	filename := fmt.Sprintf("users/%s.json", encodedUPN)
	if err := um.fss.AtomicWrite(filename, data); err != nil {
		return fmt.Errorf("保存用户文件失败: %w", err)
	}

	return nil
}
