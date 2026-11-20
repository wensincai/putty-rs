# PuTTY → Rust 改写：架构设计

## 1. 设计目标与总原则

1. **保留 PuTTY 的分层思想，不保留其实现**：`Backend`（协议）↔ `Seat`（前端回调）↔ `Terminal`（纯模型）三层在 Rust 中用 trait + 事件通道表达。
2. **复用成熟 crate 承担"重、险、专"的部分**：SSH 传输与密码学（russh）、VT 解析（vte）、pty/signal（portable-pty / crossterm）、GUI（egui）。
3. **自有实现集中在价值密度高的地方**：会话编排、主机密钥策略、终端网格模型、SFTP 传输语义、端口转发、配置/会话管理。
4. **纯函数优先，I/O 隔离**：可测逻辑不碰网络与文件系统。

## 2. Crate 分层

```
putty-rs/
├── crates/pt-core      协议与会话核心（无 UI 依赖）
│   ├── config.rs       配置模型（Config/SessionProfile/默认值/合并优先级）
│   ├── known_hosts.rs  OpenSSH known_hosts 解析、匹配、追加、指纹计算
│   ├── auth.rs         认证策略与候选顺序（password/publickey/agent/keyboard-interactive）
│   ├── agent.rs        ssh-agent 协议客户端（SSH_AUTH_SOCK / Pageant 管道）
│   ├── proxy.rs        HTTP CONNECT / SOCKS5 拨号器
│   ├── session.rs      SSH 会话生命周期（连接→握手→认证→通道），Seat 事件发射
│   ├── exec.rs         单命令执行（stdout/stderr 分流、退出码）
│   ├── shell.rs        交互式会话（pty-req、window-change、输入输出桥）
│   ├── sftp.rs         SFTP 客户端语义（列出/传输/递归/续传/进度）
│   └── forward.rs      -L / -R / -D 转发引擎
├── crates/pt-term      终端仿真器（零 I/O）
│   ├── grid.rs         单元格、行、回看缓冲、备用屏
│   ├── parser.rs       vte 解析器适配 → 语义动作
│   ├── state.rs        光标、SGR、滚动区、制表位、模式标志
│   ├── charset.rs      UTF-8 / Latin-1、宽字符宽度（unicode-width）
│   └── screen.rs       对外 API（feed(bytes)、resize(cols,rows)、dump_text()、cell(x,y)）
├── crates/pt-cli       plink 风格命令行（pt）
│   ├── 连接参数解析（clap）：user@host、-P、-i、-pw、-L/-R/-D、-batch、-v
│   ├── exec 模式 / shell 模式（raw 键盘 + 终端渲染到 stdout）
│   └── sftp 子命令：ls / get / put / mkdir / rm
└── crates/pt-gui       egui 前端（M5）
    ├── 会话管理器（列表、编辑、连接）
    ├── 终端渲染（等宽字体网格、颜色主题、选中复制）
    └── 设置（主题、字体、回看行数、默认认证）
```

依赖方向严格单向：`pt-gui → pt-cli?? 否`；`pt-gui → pt-core, pt-term`；`pt-cli → pt-core, pt-term`；`pt-core` 与 `pt-term` 互不依赖（由前端编排）。

## 3. 运行时模型

```
            ┌────────────── UI 线程（egui / crossterm 事件循环）──────────────┐
            │  键盘/尺寸事件 ──►  SessionHandle.input(bytes)                  │
            │  SeatEvent  ◄──  mpsc / crossbeam 通道  ◄── tokio 任务           │
            └────────────────────────────────────────────────────────────────┘
                                        │
                        ┌───────────────▼────────────────┐
                        │  tokio runtime（后台线程）       │
                        │  Session ─ russh client handle  │
                        │  ├ channel(pty) ⇄ shell 桥      │
                        │  ├ forward listeners            │
                        │  └ sftp subsystem               │
                        └────────────────────────────────┘
```

- **会话 = 一个 tokio 任务 + 一个句柄**。句柄提供 `send_input` / `resize` / `close` / `wait`，内部用 `mpsc` 投递命令，避免 UI 线程阻塞。
- **事件用枚举**（`SeatEvent`）：`Output(Vec<u8>)`、`StateChanged`、`HostKeyPrompt`、`AuthPrompt`、`ExitStatus`、`Error`。前端消费事件，不反向调用协议层。
- **终端模型由前端持有**（CLI 与 GUI 各一份），协议层只负责字节流转发——对应 PuTTY `Seat` 只发 `output` 的语义。

## 4. 关键设计决策

### 4.1 为什么用 russh 而不是自己实现 SSH

PuTTY 的 SSH 协议栈约 3 万行（transport2 2,722 + userauth2-client 2,621 + connection2 1,762 + kex2-client 1,062 + bpp2 999 …）。自行实现意味着：算法协商矩阵、重协商、流量控制、扩展协商、数十种边界情况。russh 为纯 Rust、无 unsafe 依赖、支持 SSH-2 全套现代算法，且已被多个生产项目使用；把预算留给终端与转发这类"用户能感知"的部分更合理。**对应关系写入 README，避免"伪重写"误解。**

### 4.2 主机密钥策略（安全关键）

```rust
pub enum HostKeyPolicy { Strict, AcceptNew, Off }
pub struct KnownHosts { path: PathBuf, entries: Vec<HostEntry> }
// 匹配规则：OpenSSH 风格 [host]:port / 通配符 * ? / 否定 ! / 哈希条目 |1|salt|hash 跳过并降级为未知
pub enum HostKeyVerdict { Match, Mismatch { old: Fingerprint, new: Fingerprint }, Unknown }
```

- 默认 `AcceptNew`（TOFU）：首次连接打印 SHA256 指纹并追加；**变更一律拒绝**，除非显式 `--host-key-policy off` 或用户交互确认（GUI）。
- 指纹格式与 OpenSSH 一致：`SHA256:<base64 无填充>`。

### 4.3 终端模型

```rust
pub struct Screen { cols: u16, rows: u16, grid: Vec<Cell>, alt: Option<Grid>, scrollback: VecDeque<Row>, ... }
pub struct Cell { ch: char, attrs: Attrs, width: u8 }   // width: 1 / 2 / 0(占位)
pub struct Attrs { fg: Color, bg: Color, bold: bool, italic: bool, underline: bool, reverse: bool, blink: bool }
```

- **解析器不自己写**：`vte::Parser` 负责字节级状态机（CSI/OSC/DCS/ESC），本项目实现 `vte::Perform`，把动作映射为网格修改——这是 Alacritty/WezTerm 的成熟做法。
- 宽字符：`unicode-width` 给出 1/2/0；0 宽（组合符）附着到前一单元格，2 宽占两格（第二格 `width=0` 占位），擦除时按格清零，避免"半个汉字"。
- 回看：`VecDeque<Row>` 上限可配（默认 2000），超出从头部弹出。
- 备用屏：`tput smcup`/vim 使用，切换时保留主屏内容与光标。
- **不实现**：bidi（阿拉伯/希伯来双向排版，原版 1,685 行）——记入已知差异；需要时再补。

### 4.4 行规程与本地回显

原版 `ldisc.c` 同时承担：本地回显、行编辑、Telnet 协商。SSH 会话中远端 PTY 已负责回显与行编辑，因此 Rust 版**只保留原始模式直通**（raw mode），本地编辑交给终端复用器或 GUI；单命令模式不需要 ldisc。这是有意的简化，避免把 Telnet 的复杂度带入 SSH 路径。

### 4.5 配置与会话

```rust
pub struct SessionProfile {
    pub name: String, pub host: String, pub port: u16, pub user: String,
    pub auth: AuthConfig, pub proxy: Option<ProxyConfig>,
    pub terminal: TerminalPrefs, pub forwards: Vec<ForwardSpec>,
}
pub struct Config { pub sessions: Vec<SessionProfile>, pub defaults: GlobalPrefs }
```
- 存储：`~/.pt-rs/sessions.json`（Windows 为 `%APPDATA%\pt-rs\`），JSON + 版本字段便于迁移。
- 合并顺序：CLI 显式参数 > 环境变量（`PT_HOST` 等）> 会话 > 内置默认。
- 密码不入盘；支持 `PT_PASSWORD` 环境变量与交互提示（不回显）。

### 4.6 端口转发

| 参数 | 实现 |
|---|---|
| `-L` | 本地 `TcpListener` → 每连接 `channel_open_direct_tcpip` → 双向 copy |
| `-R` | `tcpip_forward` 注册 → 接收 `forwarded-tcpip` 通道 → 连本地目标 |
| `-D` | 本地 listener 先读 SOCKS5 握手（无认证/CONNECT）→ 再开 direct-tcpip |

半关闭：双向 `copy_bidirectional` 不能表达单向 FIN；自写 `pump` 循环，读到 EOF 后 `shutdown(Write)` 对侧，等另一方向结束后关闭。

## 5. 与原版模块的映射

| PuTTY (C) | Rust | 说明 |
|---|---|---|
| `ssh/ssh.c` + `common.c` | `pt-core/session.rs` | 会话状态机与配置装配 |
| `ssh/transport2.c`, `bpp2.c`, `kex2-client.c` | russh | 传输层、二进制包、密钥交换 |
| `ssh/userauth2-client.c` | `pt-core/auth.rs` + russh | 认证编排（候选排序、重试、agent） |
| `ssh/connection2.c`, `sesschan.c` | russh channel API + `pt-core/shell.rs` | 通道与 PTY |
| `ssh/portfwd.c` | `pt-core/forward.rs` | 端口转发 |
| `ssh/sftp.c` (客户端) | `pt-core/sftp.rs` + russh-sftp | SFTP 客户端 |
| `ssh/agentf.c` | `pt-core/agent.rs` | agent 认证 |
| `terminal/terminal.c` | `pt-term/*` | 终端模型（解析改用 vte） |
| `unix/pty.c` | `portable-pty` / `crossterm` | 本地 pty 与 raw 模式 |
| `conf.h` + `settings.c` | `pt-core/config.rs` | 211 项 → 精选子集 + JSON |
| `unix/window.c` (GTK) | `pt-gui` (egui) | 渲染与交互 |
| `proxy/*` | `pt-core/proxy.rs` | CONNECT / SOCKS5 |
| `crypto/*` | RustCrypto / ring（经 russh） | 不自实现 |
| `linux/…` GSSAPI、`sharing.c`、`ssh/server.c` | 不实现 | 见 Non-goals |

## 6. 错误模型

```rust
pub enum PtError {
    Config(String), Dns(String), Connect(String), Proxy(String),
    HostKey(HostKeyError),      // Mismatch / Rejected / KnownHostsIo
    Auth(String),               // 全部方法失败，含最后一次原因
    Protocol(String), Channel(String), Sftp(String), Forward(String),
    Io(#[from] std::io::Error),
}
```
- 所有错误携带"下一步建议"的上下文字符串（如 `auth failed: tried password, publickey(id_ed25519); server offers publickey,keyboard-interactive`）。
- 不用 `anyhow` 贯穿库层；CLI 层再转人话。

## 7. 测试策略

| 层 | 方式 |
|---|---|
| 纯逻辑 | `pt-term` 网格/解析快照测试（喂 ANSI 序列 → 断言单元格）；`known_hosts` 匹配矩阵；SOCKS5 握手字节序列 |
| 协议 | 对本地 MSYS2 sshd：密码、公钥、exec、PTY、SFTP、转发 |
| 回归 | `tests/` 下脚本化 E2E（PowerShell + sshd 配置），CI 可用容器 sshd |
| 性能 | 10 MB 日志喂入终端，测吞吐与内存 |

## 8. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| 终端兼容性长尾（vim/tmux 特定序列） | 高 | 用 vte 解析器 + 以 tmux/vim/htop 为回归用例；逐项补动作 |
| russh 版本 API 变动 | 中 | 锁定次版本，封装 `session.rs` 隔离 |
| Windows 控制台 raw 模式差异 | 中 | 用 crossterm 抽象；非 TTY 自动降级 |
| SFTP 大文件内存 | 中 | 流式分块（256 KB），断点续传按偏移 |
| 范围膨胀（想做服务端/Pageant） | 中 | Non-goals 明确；新需求走新增里程碑 |
