# 架构

## 数据路径

```text
远端 fclaude session
  -> 官方 ego-browser Skill
  -> 不可变 Linux ego-browser wrapper
  -> owner-only Node broker socket
  -> 已认证控制面 relay
  -> macOS Bridge 主动出站连接
  -> 真实本地 ego-browser 进程
  -> ego lite 与本机已有 profile
```

wrapper 有界读取一段 heredoc，并向受信 Node broker 申请一次性 permit。binding 身份、
generation、relay ticket、单调 sequence、租约续期和 relay socket 均由 broker 管理，
wrapper 无权选择用户、设备、tool session、Node 或 generation。
broker 还会从已认证的 session nonce 派生 `agent-remote:<tool_session_id>` 并写入 permit；
wrapper 将该值复制到加密请求中，不信任 shell environment 的覆盖值。

远端 wrapper 可用于 `native` 与 `docker_sandbox` Linux Claude runtime。Node 特权 helper
从 root-owned runtime state 解析身份：Native Runtime 使用专用非 root host UID，Docker
Sandbox 使用配置的固定非 root runtime UID/GID。Docker 启动还会校验并挂载 release-pinned
wrapper、Skill 与 broker 路径。数字 POSIX ACL 只授予解析出的身份访问 broker 目录与 socket
所需的 traverse/read/write 权限；broker 随后同时校验进程内 nonce 与 Linux `SO_PEERCRED`
的准确 UID。UID 0、过期 trusted spec、mount 不匹配或身份无法解析时均不具备资格。

Server 认证并校验 outer envelope 的 channel、binding kind、binding ID、generation、
sequence、方向、密文长度和 request ID，只转发不透明密文。Server 不接收脚本、stdout、
stderr、截图字节、页面数据、URL 或本地路径。

broker 为每个请求生成随机 ChaCha20-Poly1305 key，并使用已注册的 Bridge X25519 公钥
封装。key-wrap transcript 绑定 binding、generation、request ID 与 sequence；outer
路由字段作为 AEAD associated data，relay 无法在不触发认证失败的情况下修改这些字段。

生产 Server worker 通过 Redis 共享 relay 状态。一次性 ticket 与 proof challenge 原子消费；
binding/generation/role presence 的 TTL 为 5 秒；端点专用 Pub/Sub channel 只传输 opaque frame
与 close 通知。两个 role 可以落在不同 worker。重复 role、缺失 subscriber、过期 presence、
异常共享状态或 Redis 故障都会关闭配对，不会回退到单进程 pairing。生命周期事务提交后，
PostgreSQL revocation outbox 会幂等驱动跨 worker close 通知。

## 身份与授权

Device Client 拥有独立的 Ed25519 proof-of-possession 身份和 X25519 加密 key。每次变更
先获取 Server 签发的短期一次性 challenge。签名 transcript 绑定 operation、canonical
request payload、challenge、设备与 binding generation、release/credential profile、
binding ID 和 Server host。challenge 不能重放，也不能换到其他操作或 payload。

系统不存在自动绑定或“最近 session”绑定。用户必须列出候选项、选择明确的 tool-session
ID、查看全信任警告并确认 claim。Server 将唯一合法的 Task Space label 派生为
`agent-remote:<tool_session_id>`，并拒绝客户端提交的不匹配值。Device Client 只有在 claim
或 resume 响应返回同一 label 后，才会把它写入 owner-only active-binding handoff。Bridge
从该 handoff 加载 label，并拒绝默认 label 或声明的 Task Space scope 不一致的加密请求。
只有 lease 健康、能力匹配且状态为 `active` 的 binding 可以执行请求。

## 生命周期

binding 的 lease 为 60 秒，每 20 秒续期；续期失败宽限 10 秒，absolute TTL 为 8 小时。
admission 要求至少剩余 20 秒。单次执行上限 120 秒，每个 binding 最多同时执行 4 个请求。

正常请求按 Task Space、Tab 顺序使用协作锁；冲突立即失败。scope 缺失、为 wildcard 或
无法解析时使用 binding 锁。这些锁只避免正常工作流竞态；全信任代码可以绕过。
对于官方 Skill 的正常路径，Bridge preamble 会把 `useOrCreateTaskSpace(...)` 映射到 permit
派生的专用名称。preamble 不会提前选择空间，也不会包装 `claimTaskSpace`、
`takeOverTaskSpace`、原始 CDP 或其他全信任 helper，因此明确的 handoff 恢复和文档所述的
绕过语义保持不变。

激活后，Bridge 会通过与普通请求相同的 execution supervisor 启动一个独立、只读的 ownership
monitor。monitor 脚本只调用 ego lite 原生 `listTaskSpaces()` API 并读取匹配空间的
`ownership`；它从不调用
或包装 `useOrCreateTaskSpace`、`claimTaskSpace` 或 `takeOverTaskSpace`。空间尚不存在或初始为
user-owned 不会触发停止；monitor 只有先观察到 `ownership="agent"` 后才 armed，随后从
`agent` 变为 `agentDelegatedToUser` 或 `user` 才视为接管。重复匹配、未知 ownership、进程
故障或意外退出均视为 monitor unavailable。Bridge 持有 supervisor control pipe，因此
Bridge 死亡会关闭 pipe 并终止 monitor runtime，不会留下独立 browser client。

暂停、停止、撤销、tool session 终止、lease 过期、relay 断开、policy 漂移和 generation
变化都会停止新请求。Bridge 从外部终止受监管进程组，结果未知的脚本绝不自动重放。
已经发生的副作用无法回滚；主动脱离监管的同 UID 进程不在 supervisor 保证范围内。

Task Space 被接管时，Bridge 先 revoke 本地 admission 并等待受监管执行终止，再要求
Server 用准确 generation 和 `task_space_takeover` 原因暂停 binding。monitor 丢失采用相同
顺序并使用 `task_space_monitor_unavailable`。该有界 Server 调用失败或超时也不会重新开放
本地 admission。paused binding 保留 canonical label，但 Device Client 必须再次明确确认
resume，并推进 generation。恢复时可以使用 ego lite 原生 claim/takeover helper 将 ownership
交还 agent；monitor 与 Bridge 都不会自动 claim 或 takeover。

独立 Device Client 同时是本地授权存活 peer。其当前 UID 所有、mode `0600` 的 Unix socket
每 2 秒发送固定 heartbeat。Bridge 在 connect 前后检查 socket identity、校验 peer UID、
要求首个 heartbeat，并持续执行 5 秒超时。peer 丢失时严格 fail closed：先 revoke supervisor
并终止受监管执行，再清除本地 active-binding handoff，最后最多用 10 秒尝试按 generation
停止 Server binding。即使服务端 stop 无法确认，本地 admission 也不会恢复。

## 本地数据

浏览器 profile 始终留在 Mac 上的 ego lite 中。控制面只保存身份、授权、版本、policy
digest、生命周期和审计元数据。Bridge 使用私有 work root 暂存有界 stdout、stderr 与
截图，并在收集完成后删除请求目录。

helper 文件策略会 canonicalize 配置的 root，并拒绝路径穿越、符号链接、硬链接、
非 regular file 及超过大小/数量限制的内容。该策略只保护 helper 介导的上传和 artifact
路径；全信任脚本仍拥有 Bridge 用户本来的文件系统与网络权限。

Bridge 与 Device Client 只输出 label 有限且不含正文的 JSON metric event。指标来源、告警、
containment 与恢复步骤见 `operations.zh-CN.md`。面向 launch agent 的顶层失败同样只输出有限
error code，不渲染被包装的错误正文。
