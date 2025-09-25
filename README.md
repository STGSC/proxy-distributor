# 多机场订阅聚合与二次分发平台

一个基于 Go 开发的企业级多机场订阅聚合与二次分发平台，支持 OIDC 认证、多格式订阅导出、节点管理和集合分配。

## ✨ 核心特性

- **🚀 单文件运行**：编译为单个可执行文件，无需外部依赖
- **🔐 OIDC 认证**：支持 Microsoft Entra ID 单点登录
- **📡 多订阅源聚合**：支持多个订阅源的自动抓取和解析
- **🧠 智能节点管理**：节点去重、标签分类、地理位置识别
- **📦 灵活集合分配**：支持角色绑定和个人集合分配
- **📤 多格式导出**：支持 Clash、V2RayN、sing-box、SIP008 等格式
- **🛡️ 企业级安全**：审计日志、访问控制、速率限制、水印防泄露
- **💾 文件型存储**：无需数据库，使用文件系统存储，支持原子写和 WAL

## 🚀 快速开始

### 系统要求

- **Go 1.21+** (仅编译时需要)
- **Windows 10/11** 或 **Linux** (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- **内存**: 最少 512MB，推荐 1GB+
- **磁盘**: 最少 100MB 可用空间

### 方式一：直接下载预编译版本 (推荐)

#### Windows 用户

1. **下载预编译版本**
   ```powershell
   # 使用 PowerShell 下载
   Invoke-WebRequest -Uri "https://github.com/STGSC/proxy-distributor/releases/latest/download/proxy-distributor-windows-amd64.exe" -OutFile "proxy-distributor.exe"
   ```

2. **运行程序**
   ```cmd
   # 首次运行会自动创建配置
   proxy-distributor.exe --data ./data
   ```

#### Linux 用户

1. **下载预编译版本**
   ```bash
   # 下载最新版本
   wget https://github.com/STGSC/proxy-distributor/releases/latest/download/proxy-distributor-linux-amd64 -O proxy-distributor
   
   # 添加执行权限
   chmod +x proxy-distributor
   ```

2. **运行程序**
   ```bash
   # 首次运行会自动创建配置
   ./proxy-distributor --data ./data
   ```

### 方式二：从源码编译

#### Windows 用户

1. **安装 Go**
   - 下载并安装 [Go 1.21+](https://golang.org/dl/)
   - 验证安装：`go version`

2. **克隆并编译**
   ```cmd
   # 克隆项目
   git clone https://github.com/STGSC/proxy-distributor.git
   cd proxy-distributor
   
   # 编译 Windows 版本
   go build -o proxy-distributor.exe ./cmd/api
   ```

3. **运行程序**
   ```cmd
   proxy-distributor.exe --data ./data
   ```

#### Linux 用户

1. **安装 Go**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install golang-go
   
   # CentOS/RHEL
   sudo yum install golang
   
   # 或者使用官方安装脚本
   curl -L https://git.io/vQhTU | bash
   source ~/.bashrc
   ```

2. **克隆并编译**
   ```bash
   # 克隆项目
   git clone https://github.com/STGSC/proxy-distributor.git
   cd proxy-distributor
   
   # 编译 Linux 版本
   go build -o proxy-distributor ./cmd/api
   ```

3. **运行程序**
   ```bash
   ./proxy-distributor --data ./data
   ```

## ⚙️ 配置说明

### 首次运行配置

首次运行会自动创建 `data` 目录和默认配置文件 `data/config.yml`：

```yaml
listen:
  http: ":8080"

auth:
  oidc:
    tenant_id: "<your-tenant-id>"
    client_id: "<your-client-id>"
    client_secret: "<your-client-secret>"
    redirect_url: "http://localhost:8080/auth/callback"
  session:
    cookie_name: "sid"
    secret: "your-32-byte-secret-key-here-change-me"

export:
  cache_ttl_seconds: 180

limits:
  default_rpm: 30

log:
  level: "info"
  format: "json"

azure:
  enabled: false
  tenant_id: "<your-tenant-id>"
  client_id: "<your-client-id>"
  client_secret: "<your-client-secret>"
  group_ids: []
  sync_interval: "24h"

server:
  base_url: "http://localhost:8080"
```

### OIDC 配置步骤

1. **在 Microsoft Entra ID 中创建应用注册**
   - 登录 [Azure Portal](https://portal.azure.com)
   - 导航到 "Azure Active Directory" > "应用注册"
   - 点击 "新注册"

2. **配置应用信息**
   - 名称：`Proxy Distributor`
   - 支持的账户类型：选择适合的类型
   - 重定向 URI：`http://localhost:8080/auth/callback`

3. **获取配置信息**
   - 应用(客户端) ID：在应用概览页面
   - 目录(租户) ID：在应用概览页面
   - 客户端密码：在"证书和密码"中创建

4. **配置应用角色** (推荐)
   - 在"应用角色"中添加角色：`admin`, `user`
   - 在"用户和组"中分配角色

## 🖥️ 部署指南

### Windows 部署

#### 作为 Windows 服务运行

1. **使用 NSSM 注册服务**
   ```cmd
   # 下载 NSSM (https://nssm.cc/download)
   # 解压到 C:\nssm
   
   # 注册服务
   C:\nssm\win64\nssm.exe install ProxyDistributor "C:\path\to\proxy-distributor.exe"
   C:\nssm\win64\nssm.exe set ProxyDistributor Parameters "--data C:\path\to\data"
   C:\nssm\win64\nssm.exe set ProxyDistributor Start SERVICE_AUTO_START
   
   # 启动服务
   C:\nssm\win64\nssm.exe start ProxyDistributor
   ```

2. **使用 PowerShell 脚本**
   ```powershell
   # 创建启动脚本 start.ps1
   $env:DATA_DIR = "C:\proxy-distributor\data"
   Start-Process -FilePath "C:\proxy-distributor\proxy-distributor.exe" -ArgumentList "--data", $env:DATA_DIR -WindowStyle Hidden
   ```

#### 使用反向代理 (Nginx)

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Linux 部署

#### 使用 systemd 服务

1. **创建服务文件**
   ```bash
   sudo nano /etc/systemd/system/proxy-distributor.service
   ```

2. **服务配置内容**
   ```ini
   [Unit]
   Description=Proxy Distributor
   After=network.target
   
   [Service]
   Type=simple
   User=proxy-distributor
   Group=proxy-distributor
   WorkingDirectory=/opt/proxy-distributor
   ExecStart=/opt/proxy-distributor/proxy-distributor --data /opt/proxy-distributor/data
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal
   
   [Install]
   WantedBy=multi-user.target
   ```

3. **创建用户和目录**
   ```bash
   # 创建用户
   sudo useradd -r -s /bin/false proxy-distributor
   
   # 创建目录
   sudo mkdir -p /opt/proxy-distributor
   sudo cp proxy-distributor /opt/proxy-distributor/
   sudo chown -R proxy-distributor:proxy-distributor /opt/proxy-distributor
   sudo chmod +x /opt/proxy-distributor/proxy-distributor
   ```

4. **启动服务**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable proxy-distributor
   sudo systemctl start proxy-distributor
   
   # 查看状态
   sudo systemctl status proxy-distributor
   ```

#### 使用 Docker 部署

1. **创建 Dockerfile**
   ```dockerfile
   FROM golang:1.21-alpine AS builder
   WORKDIR /app
   COPY . .
   RUN go build -o proxy-distributor ./cmd/api
   
   FROM alpine:latest
   RUN apk --no-cache add ca-certificates
   WORKDIR /root/
   COPY --from=builder /app/proxy-distributor .
   COPY --from=builder /app/web ./web
   EXPOSE 8080
   CMD ["./proxy-distributor", "--data", "./data"]
   ```

2. **构建和运行**
   ```bash
   # 构建镜像
   docker build -t proxy-distributor .
   
   # 运行容器
   docker run -d \
     --name proxy-distributor \
     -p 8080:8080 \
     -v $(pwd)/data:/root/data \
     proxy-distributor
   ```

#### 使用 Docker Compose

```yaml
version: '3.8'
services:
  proxy-distributor:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/root/data
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
```

## 📊 使用指南

### 访问 Web 界面

启动服务后，在浏览器中访问：
- **本地访问**: `http://localhost:8080`
- **远程访问**: `http://your-server-ip:8080`

### 主要功能

#### 1. 订阅源管理
- 添加多个订阅源
- 设置定时抓取计划
- 配置认证头和代理
- 监控抓取状态

#### 2. 节点管理
- 自动解析多种订阅格式
- 节点去重和分类
- 地理位置识别
- 手动添加/编辑节点

#### 3. 集合管理
- 创建节点集合
- 绑定到角色或分配给用户
- 支持集合排序和标签

#### 4. 用户管理
- OIDC 用户自动同步
- 角色权限管理
- 个人集合分配

#### 5. 订阅导出
支持多种客户端格式：
- **Clash/Mihomo**: YAML 格式
- **V2RayN**: Base64 编码的 URI 列表
- **sing-box**: JSON 格式
- **SIP008**: Shadowsocks 标准格式
- **Surge**: 支持 Surge 2/3/4/5
- **Quantumult**: 支持 Quantumult 和 QuantumultX
- **Loon**: Loon 配置格式

## 🔧 命令行参数

```bash
# 基本用法
proxy-distributor [选项]

# 选项说明
--data string        数据目录路径 (默认: "./data")
--config string      配置文件路径 (默认: "data/config.yml")
--port string        监听端口 (覆盖配置文件)
--debug              启用调试模式
--help               显示帮助信息
--version            显示版本信息

# 示例
proxy-distributor --data /opt/data --port 8080 --debug
```

## 📈 监控和维护

### 日志查看

#### Windows
```cmd
# 查看应用日志
type C:\proxy-distributor\logs\app.log

# 查看审计日志
dir C:\proxy-distributor\data\audit\
dir C:\proxy-distributor\data\access\
```

#### Linux
```bash
# 查看应用日志
journalctl -u proxy-distributor -f

# 查看审计日志
ls -la /opt/proxy-distributor/data/audit/
ls -la /opt/proxy-distributor/data/access/
```

### 数据备份

#### 冷备份
```bash
# 停止服务
sudo systemctl stop proxy-distributor

# 备份数据
tar -czf backup-$(date +%Y%m%d).tar.gz /opt/proxy-distributor/data/

# 启动服务
sudo systemctl start proxy-distributor
```

#### 热备份
```bash
# 优先同步以下文件
rsync -av /opt/proxy-distributor/data/*.snapshot.zst /backup/
rsync -av /opt/proxy-distributor/data/*.yml /backup/
rsync -av /opt/proxy-distributor/data/*.wal.zst /backup/
```

## 🛡️ 安全建议

1. **更改默认密钥**
   ```yaml
   # 修改 config.yml 中的 session.secret
   auth:
     session:
       secret: "your-32-byte-secret-key-here-change-me"
   ```

2. **使用 HTTPS**
   - 生产环境建议使用反向代理 (Nginx/Apache)
   - 配置 SSL 证书

3. **定期备份**
   - 定期备份 `data` 目录
   - 设置自动备份脚本

4. **监控日志**
   - 关注审计日志和访问日志
   - 设置日志轮转

5. **权限控制**
   - 合理配置 OIDC 角色和权限
   - 定期审查用户权限

## 🔍 故障排除

### 常见问题

#### 1. OIDC 认证失败
```bash
# 检查配置
curl -X GET "http://localhost:8080/api/me" -H "Authorization: Bearer your-token"

# 常见解决方案
# - 检查 tenant_id、client_id、client_secret 是否正确
# - 确认重定向 URI 配置正确
# - 检查网络连接
```

#### 2. 订阅源抓取失败
```bash
# 检查订阅源状态
curl -X GET "http://localhost:8080/api/providers"

# 常见解决方案
# - 检查订阅 URL 是否可访问
# - 确认认证头格式正确
# - 检查代理设置
```

#### 3. 节点解析失败
```bash
# 查看节点统计
curl -X GET "http://localhost:8080/api/nodes/stats"

# 常见解决方案
# - 确认订阅格式是否支持
# - 检查订阅内容是否有效
```

### 性能优化

#### 1. 调整缓存设置
```yaml
export:
  cache_ttl_seconds: 300  # 增加缓存时间
```

#### 2. 调整限流设置
```yaml
limits:
  default_rpm: 60  # 增加每分钟请求限制
```

#### 3. 日志级别调整
```yaml
log:
  level: "warn"  # 减少日志输出
  format: "json"
```

## 🧪 开发指南

### 项目结构

```
├── cmd/api/           # 主程序入口
├── internal/          # 内部包
│   ├── api/          # Web API
│   ├── auth/         # OIDC 认证
│   ├── audit/        # 审计日志
│   ├── collections/  # 集合管理
│   ├── config/       # 配置管理
│   ├── fss/          # 文件存储系统
│   ├── nodes/        # 节点管理
│   ├── providers/    # 订阅源管理
│   ├── ratelimit/    # 限流管理
│   ├── subscribe/    # 订阅导出
│   └── users/        # 用户管理
├── web/              # Web 界面
│   ├── static/       # 静态资源
│   └── templates/    # 模板文件
└── data/             # 数据目录
```

### 开发环境设置

#### Windows
```cmd
# 安装依赖
go mod download

# 运行测试
go test ./...

# 运行程序
go run ./cmd/api --data ./data --debug
```

#### Linux
```bash
# 安装依赖
go mod download

# 运行测试
make test

# 运行程序
go run ./cmd/api --data ./data --debug
```

### 构建命令

```bash
# 开发构建
go build -o proxy-distributor ./cmd/api

# 生产构建（优化大小）
go build -ldflags="-s -w" -o proxy-distributor ./cmd/api

# 交叉编译
# Windows
GOOS=windows GOARCH=amd64 go build -o proxy-distributor.exe ./cmd/api

# Linux
GOOS=linux GOARCH=amd64 go build -o proxy-distributor ./cmd/api

# macOS
GOOS=darwin GOARCH=amd64 go build -o proxy-distributor ./cmd/api
```

### 测试

```bash
# 运行所有测试
make test

# 运行竞态检测
make race

# 运行基准测试
make bench

# 生成覆盖率报告
make testcov
```

## 📝 API 文档

### 认证接口
- `GET /auth/login` - 登录
- `GET /auth/callback` - OIDC 回调
- `GET /auth/logout` - 登出

### 管理接口
- `GET /api/me` - 获取当前用户信息
- `GET /api/providers` - 获取订阅源列表
- `POST /api/providers` - 添加订阅源
- `GET /api/nodes` - 获取节点列表
- `GET /api/collections` - 获取集合列表
- `POST /api/collections` - 创建集合
- `GET /api/users` - 获取用户列表
- `POST /api/users/:id/subscription` - 生成订阅令牌

### 订阅接口
- `GET /sub/:token` - 导出订阅（匿名访问）

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 🔄 用户文件命名变更

### 从 v1.1.0 开始，用户文件命名规则已更改

**旧格式**: `{subject}.json` (如: `9TCafyiZMwqexLUBvAZBDHOw_rhQea3EkjNetTBDCxU.json`)
**新格式**: `{upn_local_part}.json` (如: `Xiang_Ji.json`)

### 命名规则说明

- 取 UPN 中 `@` 前的部分
- 将 `.` 替换为 `_`
- 示例: `Xiang.Ji@mattel163.com` → `Xiang_Ji.json`

### 迁移步骤

1. **停止服务**
   ```bash
   # Linux
   sudo systemctl stop proxy-distributor
   
   # Windows
   # 停止 Windows 服务或关闭程序
   ```

2. **运行迁移脚本**
   ```bash
   go run migrate_users.go ./data
   ```

3. **重启服务**
   ```bash
   # Linux
   sudo systemctl start proxy-distributor
   
   # Windows
   # 重新启动程序
   ```

### 向后兼容性

- 系统会自动检测并支持两种命名格式
- 新用户将使用 UPN 命名格式
- 现有用户文件可以继续使用，但建议迁移到新格式

## 📋 更新日志

### v1.1.0
- **用户文件命名变更**: 从 Subject 命名改为 UPN 命名
- **简化命名规则**: 使用 UPN 本地部分，将 `.` 替换为 `_`
- **向后兼容**: 支持旧格式用户文件
- **迁移工具**: 提供自动迁移脚本

### v1.0.0
- 初始版本发布
- 支持 OIDC 认证
- 支持多订阅源聚合
- 支持多格式订阅导出
- 支持节点管理和集合分配
- 支持审计日志和限流

## 📞 支持

如果您遇到问题或有任何疑问，请：

1. 查看本文档的故障排除部分
2. 检查 [Issues](https://github.com/STGSC/proxy-distributor/issues)
3. 创建新的 Issue 描述您的问题

---

**注意**: 请确保在生产环境中使用前，仔细阅读安全建议部分，并正确配置所有安全设置。

