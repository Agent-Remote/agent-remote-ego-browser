# 安全模型

## 已接受的信任边界

授权模式 `ego_browser_script_full_trust` 允许远端以 Bridge 的 macOS UID、在没有 App
Sandbox 的情况下执行任意 Node.js heredoc。权限包括完整 ego lite 浏览器能力、登录数据、
Cookie、localhost 与局域网、该用户可读的文件和环境、dynamic import、网络请求和子进程。
端到端加密只保护传输过程，不能阻止已授权端点读取或外发数据。

专用 Task Space 是官方 Skill 的导航约定，不是授权边界。显式全信任代码可以枚举、claim
或 takeover 其他 Task Space 与标签页，也可以直接使用 CDP。

在正常 wrapper 路径中，Node broker 从 nonce 绑定的 tool session 派生专用名称，并通过
一次性 permit 传递。Bridge preamble 只把 `useOrCreateTaskSpace` 映射到该名称，刻意不包装
claim、takeover、Tab 或 CDP helper。Server 在 claim 时独立派生同一 canonical 名称、拒绝
不匹配值，并把它返回给 Device Client 校验后写入 owner-only handoff。Bridge 只接受与该
绑定值一致的 request label 和 Task Space scope。

接管检测独立于 request 脚本和 helper 错误。单独的受监管 runtime 只调用
`listTaskSpaces()` 并读取原生 `ownership`；它只有在绑定空间报告 `agent` 后才 armed，随后
把 `agentDelegatedToUser` 或 `user` 视为接管。它不会调用或包装 claim、takeover 或
create/select helper。monitor unavailable 本身就是 fail-closed 事件；Bridge 死亡会关闭
supervisor control pipe 并终止 monitor runtime。

## 网络与 origin 策略

生产组件不监听公网或局域网 socket。注册只接受一个 canonical HTTPS origin：禁止
userinfo、path、query、fragment 和 redirect，API 请求也禁用 redirect。Bridge 只从同一
已保存 origin 派生 WSS，并只接受当前 binding 对应的 Server 固定 relay path。relay URL、
ticket、脚本和 key 不从项目文件或任意环境变量覆盖项读取。

`application-enforced` 并不等同于 host firewall。条件允许时运维方仍应配置主机出口策略，
并把 DNS、CA trust 和已配置 HTTPS origin 视为部署安全依赖。

## 凭据

community profile 在 `~/.config/agent-remote-ego-browser` 保存 Device Client 身份、policy、
active-binding handoff 和短期 credential。目录必须属于当前 UID 且 mode 为 `0700`；敏感
文件必须属于当前用户、为单 hard-link regular file 且 mode 为 `0600`。符号链接、额外
硬链接、其他 owner、group/world 权限、格式错误或 generation 不匹配均 fail closed。
写入使用 owner-only 临时文件与 atomic rename。

macOS 安装器把受信 release 证书 digest 单独保存为当前 UID 所有、单 hard-link、`0400`
的 regular file，并拒绝隐式证书轮换。显式同设备 key 轮换会在请求前生成并持久化仅
所有者可访问的下一 generation 身份，用新 signing key 证明持有权，拒绝 stale 或不匹配
的响应，并仅在 Server 确认后清除旧 binding handoff。中断的请求或本地部分提交会保留
pending identity，确保重试使用完全相同的 generation 与 key。设备撤销仍是独立的破坏性
流程；private key 永不进入控制面或普通日志。

首次注册前，policy 只存在于本机。一旦已有 credential，修改 Site Learning，或不采用
binding 级 CAS 修改 allowlist，都必须使用新的用户认证和同设备 PoP 注册。Server 先暂停
live binding 并使其 permit 失效；Device Client 只接受 policy 与 identity 完全匹配且包含
更高 revision credential 的响应，清除 reconnect handoff 后才提交已验证的本地 policy。
因此网络错误或不匹配响应不能静默产生 Server 从未授权、但本机已广告的 policy。

## 发布信任

`community-local-trust` 使用持久项目自签证书、Hardened Runtime、嵌套代码签名校验、
用户确认的证书 SHA-256 pin、Sigstore release-asset 签名、SBOM 与 build provenance。
它不经过 Apple notarization，也不是公共分发 profile。安装器只有在 manifest、artifact、
digest 和代码签名校验完成后才递归清除 quarantine；随后确认没有残留 quarantine 属性，
并再次校验已安装 release。

`development_local` 和 Unix-socket 模式只适用于非敏感测试，不能替代生产 transport 或
readiness 证据。

## 停止保证

supervisor 创建进程组，限制执行与输出，并在超时、撤销、lease 丢失、relay 断开或用户
接管时终止受监管进程组。这能保证受监管执行单元停止，但不能撤销浏览器、文件或网络
副作用，也不能保证清除恶意同 UID 代码主动脱离监管后创建的进程。

接管时先 revoke 本地 admission，并等待受监管执行终止，再用内容无关的
`task_space_takeover` 原因请求 generation-bound Server pause。monitor 故障使用
`task_space_monitor_unavailable`；pause 请求失败不会撤销本地 revoke。恢复必须再次明确
确认 full trust 并创建新 generation，任何组件都不会自动 claim 或 takeover 该空间。

## 日志与事件响应

不得记录或审计 heredoc、页面文本、截图、Cookie、输入值、URL、本地路径、relay ticket、
access token、private key 或 inner frame 明文。运维日志只可包含有限枚举错误码、版本、
binding/generation ID、大小、耗时和生命周期原因。
设备发起的 pause reason 仅允许有限协议枚举；Server 在持久化前把所有未知生命周期原因
统一规范为 `other`。

怀疑主机或身份失陷时：应撤销 binding 与设备，而不是依赖日常 key 轮换；停止两个用户
launch agent，轮换受影响的网站 session 和本地 secret，且只检查 Bridge 元数据日志；随后
重装已验证 release 并注册新设备身份。不得恢复旧 generation 或重放结果未知的请求。
