
---

## 🔧 快速开始 项目由trae （人工智能编程平台）开发

### 前置要求

- Go 1.21 或更高版本

### 编译

```bash
# 克隆仓库
git clone https://github.com/yourusername/ssrgo.git
cd ssrgo

# 下载依赖
go mod tidy

# 编译
go build -o ssrgo .
```

### 交叉编译（可选）

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o ssrgo-linux-amd64 .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o ssrgo.exe .

# macOS arm64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o ssrgo-mac-arm64 .
```

---

## 🚀 使用方式

ssrgo 有两种运行模式：**server**（服务端）和 **local**（本地客户端）。

### 方式一：配置文件（推荐）

#### 服务端配置 (`config-server.json`)

```json
{
    "mode": "server",
    "udp_enable": false,
    "server": "0.0.0.0",
    "port": 8388,
    "method": "rc4",
    "password": "123456",
    "protocol": "auth_aes128_md5",
    "protocol_param": [
        "1:password",
        "2:password",
        "3:password"
    ],
    "local_port": 1080,
    "process_count": 5
}
```

启动服务端：

```bash
./ssrgo -c config-server.json
```

#### 本地客户端配置 (`config-local.json`)

```json
{
    "mode": "local",
    "udp_enable": false,
    "server": "你的服务器IP地址",
    "port": 8388,
    "method": "rc4",
    "password": "123456",
    "protocol": "auth_aes128_md5",
    "protocol_param": [
        "1:password",
        "2:password",
        "3:password"
    ],
    "local_port": 1080,
    "process_count": 5
}
```

启动本地客户端：

```bash
./ssrgo -c config-local.json
```

然后在浏览器/系统中设置代理为 `SOCKS5 127.0.0.1:1080` 或 `HTTP 127.0.0.1:1080`。

### 方式二：命令行参数

```bash
# 服务端
./ssrgo -mode server -port 8388 -method rc4 -password "abc@abc" \
        -protocol auth_aes128_md5 -protocol-param "1:password,2:password"

# 本地客户端
./ssrgo -mode local -server 1.2.3.4 -port 8388 -method rc4 \
        -password "abc@abc" -protocol auth_aes128_md5 -local-port 1080
```

### 命令行参数一览

| 参数 | 缩写 | 说明 | 默认值 |
|------|------|------|--------|
| `-config` | `-c` | JSON 配置文件路径 | 无 |
| `-mode` | | 运行模式：`server` 或 `local` | `server` |
| `-server` | | 服务端地址（local 模式生效） | `127.0.0.1` |
| `-port` | | 服务端监听端口 | `8080` |
| `-method` | | 加密算法 | `rc4` |
| `-password` | | 加密密码 | `1234@567` 客户端和服务器端密码要一致 |
| `-protocol` | | 协议类型 | `auth_aes128_md5` |
| `-protocol-param` | | 协议参数（逗号分隔） | 无 |
| `-local-port` | | 本地 SOCKS5 代理端口 | `1080` |
| `-process-count` | | 工作协程数 | `5` |
| `-udp` | | 启用 UDP 中继 | `false` |

> 💡 命令行参数会覆盖配置文件中的对应值。

---

## 🔐 支持的加密方式

### 流加密（Stream Cipher）
- `none` — 无加密（不推荐生产环境使用）
- `rc4`
- `rc4-md5`
- `rc4-md5-6`
- `bf-cfb`
- `cast5-cfb`
- `des-cfb`
- `idea-cfb`
- `rc2-cfb`
- `seed-cfb`
- `aes-128-cfb` / `aes-192-cfb` / `aes-256-cfb`
- `aes-128-ctr` / `aes-192-ctr` / `aes-256-ctr`
- `camellia-128-cfb` / `camellia-192-cfb` / `camellia-256-cfb`
- `chacha20`
- `chacha20-ietf`

### AEAD 加密（认证加密）
- `aes-128-gcm` / `aes-192-gcm` / `aes-256-gcm`
- `chacha20-poly1305`
- `chacha20-ietf-poly1305`
- `xchacha20-ietf-poly1305`

---

## 📡 支持的协议

| 协议 | 说明 | 备注 |
|------|------|------|
| `origin` | 原生 Shadowsocks 协议 | 无认证，兼容性好 |
| `auth_aes128_md5` | SSR 协议，AES-128 + MD5 认证 | 支持多用户 |
| `auth_aes128_sha1` | SSR 协议，AES-128 + SHA1 认证 | 支持多用户 |

### 多用户配置示例

在 `protocol_param` 数组中按 `用户ID:密码` 格式配置多个用户：

```json
{
    "protocol_param": [
        "1:alice_password",
        "2:bob_password",
        "3:charlie_password"
    ]
}
```

---

## 🧪 运行测试

```bash
go test ./...
```

---

## 🏗️ 工作原理

### 本地客户端 (Local)

1. 监听本地 `local_port`，接受 SOCKS5 或 HTTP CONNECT 请求
2. 解析目标地址，组装 Shadowsocks 地址头
3. 使用配置的加密算法和协议对数据进行加密/封装
4. 连接远端 ssrgo server，转发加密流量

### 服务端 (Server)

1. 在 `port` 上监听来自客户端的加密连接
2. 解密数据，解析 Shadowsocks 地址头得到目标地址
3. 建立到目标服务器的连接，双向转发流量

---

## 📄 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `golang.org/x/crypto` | v0.17.0 | ChaCha20、ChaCha20-Poly1305、HKDF |
| `golang.org/x/sys` | v0.15.0 | 间接依赖 |

---

## ⚠️ 免责声明

本项目仅用于学习和研究目的。请遵守当地法律法规，合法合规地使用网络工具。

---

## 📝 License

[MIT License](LICENSE)

1. 在 `port` 上监听来自客户端的加密连接
2. 解密数据，解析 Shadowsocks 地址头得到目标地址
3. 建立到目标服务器的连接，双向转发流量

---

## 📄 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `golang.org/x/crypto` | v0.17.0 | ChaCha20、ChaCha20-Poly1305、HKDF |
| `golang.org/x/sys` | v0.15.0 | 间接依赖 |

---

## ⚠️ 免责声明

本项目仅用于学习和研究目的。请遵守当地法律法规，合法合规地使用网络工具。

---

## 📝 License

[MIT License](LICENSE)