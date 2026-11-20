# PuTTY → Rust 改写：需求与功能分析

- 基线版本：PuTTY **0.85**（`putty-src/version.h`）
- 源码规模：**约 225,000 行 C**（.c/.h），71 个顶层条目，MIT 许可证
- 本文档目标：界定"改写什么、不做什么、先做什么"，作为架构设计与研发计划的输入

## 1. 基线模块构成

| 模块 | 行数（约） | 职责 | 改写取舍 |
|---|---|---|---|
| `unix/` | 46,500 | Unix/macOS 前端：GTK 窗口、字体、剪贴板、pty、plink/pscp/psftp 命令行入口 | 部分改写：pty 封装、CLI 入口；GUI 用 egui 替代 GTK |
| `windows/` | 28,600 | Win32 前端：窗口、自绘控件、注册表配置、Pageant、安装器 | **不逐行改写**：配置改 JSON，GUI 用 egui，Pageant 用 agent 协议客户端 |
| `ssh/` | 29,900 | SSH 协议栈：传输层、kex、认证、连接层、通道、端口转发、SFTP/SCP 服务端、连接共享 | **核心改写目标**；传输层用 russh，其余（会话/转发/SFTP 客户端）自研 |
| `crypto/` | 24,600 | 自有密码学：AES/ChaCha20/Poly1305、SHA-1/256/512、RSA/ECDSA/Ed25519、Argon2、DH | **不复刻**：改用 RustCrypto / ring（经 russh 引入），避免自实现密码学 |
| `terminal/` | 10,800 | 终端仿真器（8,185 行 terminal.c）+ 双向文本（bidi） | **核心改写目标**：自研 `pt-term` 网格模型 + 解析器 |
| `proxy/` | 4,450 | HTTP CONNECT / SOCKS4/5 / telnet 代理 | 自研 `pt-core::proxy`（可复用前项目经验） |
| 顶层（`.c`） | 34,100 | ldisc、配置、会话存储、对话框、cmdline、charset 转换 | 分散改写：配置模型、行规程、字符集 |

## 2. 原版关键抽象（改写时的对应锚点）

- **Backend / Seat**：后端（ssh/telnet/serial/raw）通过 `Seat` 回调向前端索要素材（输出、回声、用户名密码询问、主机密钥确认）；`BackendVtable` 定义后端生命周期。
- **Terminal**：纯数据模型（网格 + 属性 + 滚动回看 + 备用屏 + 滚动区 + 字符集 + 鼠标/选择），不含任何绘制代码。
- **Ldisc**（行规程）：终端与后端之间的中间层，处理本地回显、行编辑、Telnet 协商字符。
- **Conf**：211 项配置的扁平结构 + 保存/加载映射（注册表 / `~/.putty/sessions`）。

> 这四层是 PuTTY 可移植性的关键，Rust 改写必须保留同样的分层，否则后续加功能会重新耦合。

## 3. 用户与场景

| 角色 | 场景 | 关键需求 |
|---|---|---|
| 运维/开发 | 日常登录 Linux 服务器，跑 vim/top/htop | 终端仿真正确、响应快、中文/宽字符正常 |
| 自动化脚本 | 非交互执行远端命令、取退出码 | `pt host cmd` 单命令模式、退出码透传、stdout/stderr 分离 |
| 文件搬运 | 上传/下载/同步目录 | SFTP get/put/ls、递归、断点续传、权限保留 |
| 内网穿透 | 通过跳板机访问数据库/Web | `-L` 本地转发、`-R` 远程转发、`-D` SOCKS5 |
| 安全敏感用户 | 首次连接校验主机指纹 | known_hosts 校验、指纹展示、变更告警 |

## 4. 功能需求

### FR-1 连接与传输（P0）
- FR-1.1 支持 `ssh://user@host:port` 与 `user@host` 简写；IPv4/IPv6/域名
- FR-1.2 SSH-2 传输：算法协商由 russh 提供（curve25519-sha256、aes256-gcm、chacha20-poly1305、hmac-sha2-256 等）
- FR-1.3 主机密钥校验：OpenSSH `known_hosts` 格式读取/追加；策略 `strict`（拒绝未知）/`accept-new`（TOFU）/`off`
- FR-1.4 指纹展示：SHA256 base64（OpenSSH 风格）+ MD5 十六进制
- FR-1.5 保活：`keepalive_interval`，超时断开并报错
- FR-1.6 代理：HTTP CONNECT、SOCKS5（含用户名密码），用于 SSH 连接本身

### FR-2 认证（P0）
- FR-2.1 密码认证
- FR-2.2 公钥认证：`~/.ssh/id_ed25519` 等 OpenSSH 私钥，支持带 passphrase
- FR-2.3 ssh-agent 认证（`SSH_AUTH_SOCK`）
- FR-2.4 keyboard-interactive（P1，用于 OTP/2FA）
- FR-2.5 认证方式可排序、可禁用（`-o PreferredAuthentications=...` 风格）

### FR-3 会话（P0）
- FR-3.1 单命令执行：`pt [-batch] user@host -- cmd args`，透传退出码，stdout/stderr 分离
- FR-3.2 交互式 shell：请求 PTY、raw 模式、窗口尺寸变化（SIGWINCH → window-change）
- FR-3.3 终端仿真：VT100/xterm 子集——光标移动、SGR（16/256/真彩色）、滚动区、备用屏、制表位、自动换行、插入/删除行、擦除、OSC 标题、DCS 忽略
- FR-3.4 字符集：UTF-8（默认）、Latin-1 回退；宽字符（CJK）双宽、组合字符
- FR-3.5 滚动回看（默认 2000 行）、PgUp/PgDn、复制粘贴（CLI 下交给终端复用器/系统）
- FR-3.6 断线重连与"连接已关闭"状态提示（P1）

### FR-4 文件传输（P1）
- FR-4.1 SFTP：`ls`、`get`、`put`、`mkdir`、`rm`、`rename`、`chmod`、`stat`
- FR-4.2 递归传输（`-r`）、通配符展开
- FR-4.3 断点续传（远端 `size` 比对 + 偏移续写）
- FR-4.4 进度显示（字节/速率/ETA），非 TTY 时退化为静默

### FR-5 端口转发（P1）
- FR-5.1 `-L [bind:]lport:host:hport` 本地转发
- FR-5.2 `-R [bind:]rport:host:hport` 远程转发（`tcpip-forward`）
- FR-5.3 `-D [bind:]port` 动态转发（SOCKS5，CONNECT 命令子集）
- FR-5.4 多路并发、半关闭（FIN 单向传递）、连接失败诊断

### FR-6 配置与会话管理（P1）
- FR-6.1 会话（host/port/user/auth/key/proxy/terminal 尺寸/颜色主题）持久化到 `~/.pt-rs/sessions.json`
- FR-6.2 CLI 覆盖优先级：命令行 > 环境变量 > 会话配置 > 默认值
- FR-6.3 不在配置文件中明文保存密码（可保存 key 路径、agent 开关）

### FR-7 图形界面（P2）
- FR-7.1 终端渲染：等宽字体、256 色/真彩、粗体/斜体/下划线/反显、光标形状
- FR-7.2 会话管理器：列表、新建/编辑/删除、连接
- FR-7.3 复制粘贴、滚动、窗口缩放（字符网格重排）
- FR-7.4 明暗主题

### FR-8 可观测性（P0）
- FR-8.1 `-v` 分级日志：连接、kex、认证尝试、通道、转发；敏感信息（密码、私钥、session id 之外的密钥材料）不落日志

## 5. 非功能需求

| 编号 | 要求 |
|---|---|
| NFR-1 | 代码安全：`#![forbid(unsafe_code)]`（除非有充分理由并在评审中记录）；不自行实现密码学 |
| NFR-2 | 跨平台：Windows / Linux / macOS 单套代码（pty 用 `portable-pty` 或平台条件编译） |
| NFR-3 | 性能：终端解析 ≥ 10 MB/s 吞吐；10 万行输出不卡顿；内存随回看行数线性 |
| NFR-4 | 可靠性：连接异常、网络中断、远端 RST 均返回明确错误而非 panic |
| NFR-5 | 可测试性：协议/终端模型/配置层纯函数化，单测覆盖；E2E 对真实 sshd |
| NFR-6 | 可扩展性：新增后端（telnet/serial）或新通道类型不改动前端 |

## 6. 明确不做（Non-goals，本期）

| 项 | 理由 |
|---|---|
| Telnet / Rlogin / Serial / Raw 后端 | MIT 原版仍在，Rust 版聚焦 SSH；架构预留 `Backend` trait |
| SSH 服务端（PuTTY 0.85 新增的 `ssh/server.c`） | 场景为客户端；后续可作为独立里程碑 |
| Pageant 服务端协议、PuTTYgen GUI | 可用系统 agent + `ssh-keygen`；预留 `agent` 模块 |
| GSSAPI / Kerberos | 依赖重、受众窄；接口预留 |
| 连接共享（sharing.c，2,176 行） | 与 PuTTY 特有 IPC 强绑定，跨语言复用价值低 |
| 逐行移植 crypto/ | 自实现密码学是负资产；用审计过的 crate |
| PuTTY 注册表配置兼容 | 改用 JSON；提供一次性导入脚本（P2） |

## 7. 需求优先级汇总

| 优先级 | 需求 | 里程碑 |
|---|---|---|
| P0 | FR-1、FR-2.1~2.3、FR-3.1~3.4、FR-8 | M1 / M2 |
| P1 | FR-2.4~2.5、FR-3.5~3.6、FR-4、FR-5、FR-6 | M2 / M3 / M4 |
| P2 | FR-7、PuTTY 配置导入、Telnet 后端 | M5 / 后续 |

## 8. 验收基线

- 能登录本机 MSYS2 sshd 与 GitHub（`ssh -T git@github.com` 等价路径）
- `vim`/`top`/`htop` 交互正常，中文与 emoji 宽度正确，窗口缩放后不错行
- 1 GB 文件 SFTP 传输校验一致；`-L`/`-R`/`-D` 各有一条可复现的连通性用例
- `cargo test` 全绿、`cargo clippy` 零警告、release 构建产物可直接运行
