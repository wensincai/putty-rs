# PuTTY → Rust 改写：研发计划

## 1. 里程碑总览

| 里程碑 | 目标 | 交付物 | 验收标准 |
|---|---|---|---|
| **M0** | 立项与骨架 | 三份文档、workspace、依赖锁定、CI 脚本 | `cargo check`/`test` 通过；文档评审通过 |
| **M1** | SSH 传输闭环 | `pt` 单命令模式：连接→主机密钥→认证→exec→退出码 | 对 MSYS2 sshd 与 GitHub 完成认证；密钥错误/指纹变更被正确拒绝 |
| **M2** | 交互式会话 | PTY + 终端仿真 + raw 键盘 + 窗口缩放 | `vim`/`top`/中文/宽字符正常；`stty size` 随窗口变化 |
| **M3** | 文件传输 | SFTP `ls/get/put/mkdir/rm`，递归 + 续传 + 进度 | 1 GB 文件往返 MD5 一致；中断后续传字节数正确 |
| **M4** | 端口转发 | `-L` / `-R` / `-D` | 三条链路各一条可复现用例（HTTP 与原始 TCP） |
| **M5** | GUI 与会话管理 | `pt-gui`（egui）：列表、终端渲染、设置、主题 | 图形界面连接成功、可交互、可复制粘贴、会话持久化 |
| **收尾** | 质量与发布 | 文档更新、CI、Release、GitHub 仓库 | clippy 零警告、测试全绿、README/MIT 合规 |

## 2. M0 — 立项与骨架

**工作项**
1. 源码勘察：模块行数、关键抽象（Backend/Seat/Terminal/Ldisc/Conf）、许可证（MIT）。
2. 需求与功能分析：功能需求 FR-1~FR-8、非功能 NFR、Non-goals。
3. 架构设计：crate 分层、运行时模型、主机密钥策略、终端模型、映射表、错误模型、测试策略。
4. workspace 脚手架：`pt-core` / `pt-term` / `pt-cli` / `pt-gui`，统一依赖版本，`tracing` 日志。
5. 错误类型与配置模型落位（后续里程碑的公共契约）。

**风险**：范围过大 → 以 Non-goals 锁边界；依赖版本不稳 → 锁次版本。

## 3. M1 — SSH 传输闭环

**范围**
- `pt-core/session.rs`：连接（含 DNS、超时、保活）、主机密钥校验、认证编排、会话结束清理。
- `pt-core/known_hosts.rs`：解析（含 `[host]:port`、通配符、哈希条目识别）、匹配、追加、指纹（SHA256/MD5）。
- `pt-core/auth.rs`：password / publickey（含 passphrase）/ agent；候选顺序与失败聚合。
- `pt-core/exec.rs`：请求 `exec`，stdout/stderr 分流，`exit-status` 透传。
- `pt-cli`：`pt [opts] user@host -- cmd`，`-batch`、`-v`、`-i`、`-pw`、`-o`、`-P`。
- 代理拨号（CONNECT/SOCKS5）接入连接建立路径。

**验收**
- `pt -batch wensincai@github.com -- ` → 成功打印 GitHub 欢迎语（公钥认证 + 无 PTY）。
- 本机 sshd：密码认证成功；错误密码返回 `Auth` 错误且不泄漏密码。
- known_hosts 首次写入后二次连接不再提示；篡改指纹后连接被拒绝并给出新旧指纹。

## 4. M2 — 交互式会话与终端仿真

**范围**
- `pt-core/shell.rs`：`pty-req`（TERM、尺寸、模式位）、`window-change`、输入桥、SIGWINCH 订阅。
- `pt-term`：网格、属性、回看、备用屏、滚动区、制表位、插入/删除、擦除、SGR（16/256/真彩）、DEC 私有模式子集、OSC 0/2 标题、宽字符。
- `pt-cli`：raw 模式（crossterm）、alt-screen 输出、Ctrl-C/Ctrl-D 语义、`--dump-after` 调试选项。
- 终端渲染到 stdout：整屏重绘 + 差异刷新（CLI 版），作为 GUI 的先行验证。

**验收**
- `vim` 打开/编辑/保存、`:q` 后恢复主屏；`htop` 颜色与刷新正常。
- `printf '\e[31mred\e[0m 中文 😀\n'` 颜色与宽度正确。
- 改变窗口大小后 `stty size` 同步；`tmux` 内嵌套运行不花屏（基本用例）。

## 5. M3 — SFTP 文件传输

**范围**
- `pt-core/sftp.rs`：会话建立（`subsystem sftp`）、`ls`（长格式）、`get`（含续传）、`put`（含 `--append`）、`mkdir -p`、`rm`、`rename`、`chmod`、`stat`。
- 递归（`-r`）、通配符、并发度（默认 4 个在途请求）、进度条（indicatif）。
- 大文件流式（256 KB 块）；保留 mtime/权限（`--preserve`）。

**验收**
- 1 GB 文件上传 + 下载，MD5 与源一致；峰值内存 < 32 MB。
- 中断（Ctrl-C）后重跑 `get`，从远端 size 处续传，最终 MD5 一致。

## 6. M4 — 端口转发

**范围**
- `-L`：本地监听 → `direct-tcpip` → 双向泵（半关闭正确）。
- `-R`：`tcpip-forward` → `forwarded-tcpip` → 本地目标。
- `-D`：SOCKS5（无认证 + 用户名密码、CONNECT、IPv4/域名/IPv6）。
- 连接失败诊断、并发上限、`--exit-on-forward-failure`。

**验收**
- `-L 8080:127.0.0.1:80` 通过远端访问 HTTP 成功。
- `-R` 由远端 `curl localhost:PORT` 打通本地服务。
- `-D` 配合 `curl --socks5-hostname` 访问外网成功。

## 7. M5 — GUI 与会话管理

**范围**
- `pt-gui`：egui + 自绘等宽网格；字体（embedded / 系统等宽）；颜色主题（PuTTY 默认色板 + 明暗）；光标闪烁；选中复制、中键/快捷键粘贴；滚动条与回看。
- 会话管理器：列表、新建/编辑（host/port/user/auth/key/proxy/forward/terminal）、删除、连接；`sessions.json` 持久化。
- 连接对话框：主机密钥确认（显示指纹）、密码输入（掩码）、错误提示。
- 快捷键：Ctrl+Shift+C/V、Ctrl+±字体、Ctrl+滚轮缩放。

**验收**
- GUI 连接本机 sshd，`vim` 可用，粘贴中文正常，窗口缩放不错行。
- 会话保存后重启应用仍在；密码不落盘。

## 8. 质量门禁（每个里程碑）

1. `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test` 全绿。
2. 新增公共 API 必须有文档注释与至少一个单测/集成测试。
3. 涉及安全的改动（认证、主机密钥、密钥文件处理）需在 PR 描述中列出威胁模型影响。
4. 每个里程碑结束时更新本文档"进度"节与 README 特性表。

## 9. 测试环境

| 环境 | 用途 |
|---|---|
| 本机 MSYS2 sshd（`/c/msys64/usr/bin/sshd`，高端口 + 临时 host key） | 密码/公钥/PTY/SFTP/转发全链路 |
| `ssh -T git@github.com` 等价路径 | 真实公网 SSH-2、无 PTY exec、退出码 |
| 容器化 sshd（CI） | 可重复的回归；rm 掉本地依赖 |
| 合成 ANSI 序列 | 终端模型快照测试 |

## 10. 进度

- [x] M0 文档与 workspace（4 crate，依赖锁定，tracing）
- [x] M1 SSH 传输闭环：连接/代理、known_hosts + TOFU、SHA256/MD5 指纹、公钥/密码/agent、exec、退出码、-v 日志
- [x] M2 交互式会话与终端：pty-req、window-change、raw 键盘、`pt-term`（网格/SGR/备用屏/滚动区/宽字符/DEC 图形/DSR 应答）
- [x] M3 SFTP：ls/get/put/mkdir/rm、递归、断点续传、进度、256 KB 流式
- [x] M4 端口转发：`-L`、`-D`（SOCKS5，含用户名密码子协商）；`-R` 明确报错（见差异表）
- [x] M5 GUI：会话管理器、终端网格渲染、选择复制、明暗主题、`sessions.json`
- [x] 质量门禁：`cargo test` 39 项全绿、`cargo clippy --workspace --all-targets` 0 警告、release 构建通过
- [x] 端到端验证（GitHub / 本机 MSYS2 sshd / HTTP+SOCKS 隧道）
- [ ] 后续：`-R` 远程转发、keyboard-interactive、终端 reflow、Telnet 后端

## 11. 已知差异（相对 PuTTY 0.85）

| 差异 | 说明 |
|---|---|
| **`-R` 远程转发未实现** | 传输层 crate 未向客户端暴露 `forwarded-tcpip` 入站通道。CLI 会给出明确错误并建议在对端使用 `-L`。这是本期唯一的功能缺口 |
| 无 Telnet/Rlogin/Serial/Raw 后端 | 架构预留，未实现 |
| 无 SSH 服务端 | 客户端优先 |
| 无 bidi | 阿拉伯/希伯来双向排版未实现 |
| 无连接共享 | PuTTY 特有 IPC |
| 无 Pageant 服务端 | 走系统 agent / OpenSSH agent 协议 |
| 配置格式不兼容 PuTTY 注册表 | JSON；导入脚本为后续项 |
| 终端不做 reflow | 改宽度按行截断/补空 |
| keyboard-interactive 未实现 | 2FA/OTP 暂不可用 |
