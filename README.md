# putty-rs

**PuTTY 的 Rust 改写项目** —— 基于对 [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/) **0.85** 源码（约 22.5 万行 C，MIT 许可）的研读与逆向分析，用 Rust 重写的 SSH 客户端。目标是得到一个**可长期扩展**的代码库：分层清晰、无 `unsafe`、每个子系统都有测试，方便在此基础上加新功能。

> **项目来源说明**：本项目不是 PuTTY 的 fork，而是一次独立的**重写（rewrite）**。协议线格式与密码学交由成熟的 crate（`russh`）负责，本项目实现的是会话编排、主机密钥策略、终端仿真语义、SFTP 传输语义、端口转发与前端——也就是原版中"用户能感知"的部分。原版为 MIT 许可，本项目沿用 MIT 并在 `LICENSE` 中保留 Simon Tatham 的版权声明。

## 特性

| 能力 | 状态 | 对应原版模块 |
|---|---|---|
| SSH-2 传输、密钥交换、加密 | ✅ 通过 `russh`（curve25519/aes-gcm/chacha20-poly1305…） | `ssh/transport2.c` `ssh/kex2-client.c` `ssh/bpp2.c` |
| 主机密钥校验（known_hosts + TOFU）、SHA256/MD5 指纹 | ✅ 自研 `pt-core/known_hosts.rs` | `ssh/…` + `windows/…` host key 对话框 |
| 认证：公钥 / 密码 / ssh-agent | ✅ | `ssh/userauth2-client.c` `ssh/agentf.c` |
| 单命令执行（退出码透传，stdout/stderr 分离） | ✅ | `unix/plink.c` |
| 交互式会话（PTY、窗口尺寸、raw 键盘） | ✅ | `ssh/sesschan.c` `unix/pty.c` |
| 终端仿真（VT100/xterm 子集、256 色/真彩、备用屏、滚动区、宽字符） | ✅ 自研 `pt-term` | `terminal/terminal.c`（8,185 行） |
| SFTP：ls/get/put/mkdir/rm，递归、续传、进度 | ✅ | `ssh/sftp.c` |
| 端口转发 `-L` / `-D`（SOCKS5） | ✅ | `ssh/portfwd.c` |
| 端口转发 `-R` | ⚠️ 见「已知差异」 | `ssh/portfwd.c` |
| 代理（HTTP CONNECT / SOCKS5） | ✅ | `proxy/` |
| GUI（egui）：终端渲染、会话管理、主题 | ✅ | `unix/window.c` `windows/window.c` |
| Telnet / Serial / Rlogin / Raw 后端 | ❌ 未实现 | `telnet.c` `unix/serial.c` 等 |
| SSH 服务端、连接共享、Pageant 服务端、bidi | ❌ 未实现 | `ssh/server.c` `ssh/sharing.c` `terminal/bidi.c` |

## 架构

```
crates/
  pt-core/   会话与协议核心（无 UI 依赖）
    session.rs    连接 → 主机密钥 → 认证 → 通道
    known_hosts.rs  OpenSSH known_hosts 解析/匹配/追加 + 指纹
    auth.rs       认证编排与失败诊断
    proxy.rs      HTTP CONNECT / SOCKS5 拨号
    exec.rs       单命令执行
    shell.rs      PTY 会话与输入泵
    sftp.rs       SFTP 语义（递归/续传/进度）
    forward.rs    -L / -D / -R
    config.rs     会话配置（JSON）
  pt-term/   终端模型（零 I/O）
    screen.rs     网格、光标、滚动区、备用屏、VT 解析适配（vte）
    cell.rs       单元格与 SGR 属性
  pt-cli/    `pt`：plink 风格命令行 + `pt sftp` 子命令
  pt-gui/    `pt-gui`：egui 前端（会话列表、终端网格、选择复制）
```

依赖方向单向：`pt-cli`/`pt-gui` → `pt-core` + `pt-term`；`pt-core` 与 `pt-term` 互不依赖。

设计文档见 `docs/`：

- [需求与功能分析](docs/PuTTY改写_需求与功能分析.md)
- [架构设计](docs/PuTTY改写_架构设计.md)
- [研发计划](docs/PuTTY改写_研发计划.md)

## 构建

需要 Rust 1.85+。

```powershell
cargo build --release     # target/release/pt.exe 与 pt-gui.exe
cargo test                # 39 个单元测试
```

## 使用

```powershell
# 单命令（等价 plink user@host cmd）
pt user@host -- uname -a
pt -P 2222 user@host -- "systemctl status nginx"

# 交互式 shell（需要真实终端；--force-pty 供脚本测试）
pt user@host
pt -i C:\Users\me\.ssh\id_ed25519 user@host

# 通过代理连接
pt --proxy socks5://127.0.0.1:1080 user@host
pt --proxy http://user:pass@proxy:3128 user@host

# 主机密钥策略
pt --host-key-policy strict user@host      # 只信任 known_hosts 中已有的
pt -o UserKnownHostsFile=C:\tmp\kh user@host

# 端口转发
pt -N -L 8080:db.internal:5432 user@host   # 本地转发
pt -N -D 1080 user@host                    # SOCKS5 动态转发

# SFTP
pt sftp ls   user@host:/var/log
pt sftp get  user@host:/var/log/syslog .\syslog --resume
pt sftp put  .\build.zip user@host:/tmp/ -r
pt sftp mkdir user@host:/tmp/releases
pt sftp rm   user@host:/tmp/releases -r

# GUI
pt-gui
```

认证顺序默认 `publickey,agent,password,keyboard-interactive`，可用 `-o PreferredAuthentications=password` 调整；密码优先取 `$PT_PASSWORD`，否则交互提示（不回显）。

配置与会话保存在 `%APPDATA%\pt-rs\sessions.json`（Windows）或 `~/.config/pt-rs/sessions.json`。密码不写入磁盘。

## 验证

- `cargo test --workspace`：**39 项全绿**（known_hosts 匹配矩阵与通配符/否定、指纹向量、Digest… 端口转发解析、终端网格/SGR/备用屏/宽字符/滚动区、GUI 键位映射）
- `cargo clippy --workspace --all-targets`：**0 警告**
- 真实环境端到端：
  - GitHub（`git@github.com`）：公钥认证成功，`--host-key-policy strict` 正确拒绝未知主机，篡改 known_hosts 后报 `HOST KEY CHANGED` 并给出新旧指纹
  - 本机 MSYS2 sshd：`exec` 返回远端退出码；PTY 会话申请成功（`SSH_TTY=/dev/pty0`），`stty size` 与服务端窗口尺寸一致，`window-change` 生效
  - SFTP：2 MB 文件 `put` → `get` 往返 MD5 一致；`ls/mkdir/rm` 可用
  - 转发：`-L 18080→http:8099` 与 `-D`（SOCKS5，IP 与域名两种）均返回 HTTP 200
  - GUI：启动正常，窗口标题/会话列表/终端网格渲染

## 已知差异（相对 PuTTY 0.85）

| 差异 | 说明 |
|---|---|
| `-R` 远程转发未实现 | 当前 SSH 传输 crate 未向客户端暴露 `forwarded-tcpip` 入站通道；错误信息会提示改用对端 `-L` |
| 无 Telnet / Serial / Rlogin / Raw 后端 | 架构预留 `Backend` 分层，未实现 |
| 无 SSH 服务端 | PuTTY 0.85 新增的服务端不在本期范围 |
| 无 bidi（双向文本） | 阿拉伯/希伯来排版未实现 |
| 无连接共享（sharing.c） | 与 PuTTY 特有 IPC 强绑定 |
| 无 Pageant 服务端 | 走 OpenSSH agent 协议 / Pageant 客户端 |
| 终端不做 reflow | 改变窗口宽度时按行截断/补空，不做自动重排 |
| 配置格式为 JSON | 不兼容 PuTTY 注册表/`~/.putty/sessions` |
| keyboard-interactive 未实现 | 2FA/OTP 场景暂不可用 |
| 在 mintty / Git Bash 中运行 CLI 没有 PTY | 这类终端给子进程的是管道而非控制台，`pt` 检测到 stdin 非终端后不会申请 PTY（行为同 `ssh -T`）：Tab 补全失效、vim 无法切换模式。会打印警告；可改用 Windows Terminal / cmd / PowerShell，或加 `--force-pty` |

## 许可证

MIT，见 [`LICENSE`](LICENSE)。本项目为 PuTTY 的独立改写，不是 fork，也不包含 PuTTY 源码；原版版权归 **Simon Tatham** 及贡献者所有，其原始许可声明完整保留在 [`LICENSE-PUTTY`](LICENSE-PUTTY) 中。
