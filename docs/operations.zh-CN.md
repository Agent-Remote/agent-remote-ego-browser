# 安装与运维

## 前置条件

- macOS 已登录 GUI 用户，且 ego lite 已安装
- 远端 Claude session 使用符合条件的 Linux `native` 或 `docker_sandbox` runtime backend，
  且 wrapper、Skill、broker mount、身份与 ACL 合同均已验证
- 官方本地 `ego-browser` runtime `0.4.7.4`
- Agent Remote Server 的 HTTPS origin 与用户 registration token
- `cosign`、`python3`、`plutil`、`launchctl`、`codesign` 和 macOS 标准工具
- release archive、release manifest 及两者的 Sigstore bundle
- 通过独立可信渠道取得的项目签名证书 SHA-256

安装器不会安装、修改或删除 ego lite。

## 校验与安装

```sh
./installer/install-macos.sh \
  --archive agent-remote-ego-browser-macos-universal-0.1.0.tar.gz \
  --archive-sigstore-bundle agent-remote-ego-browser-macos-universal-0.1.0.tar.gz.sigstore.json \
  --manifest agent-remote-ego-browser-0.1.0.release-manifest.json \
  --manifest-sigstore-bundle agent-remote-ego-browser-0.1.0.release-manifest.json.sigstore.json \
  --certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm-local-trust
```

`ego-browser` 不在 `PATH` 时使用 `--ego-browser /absolute/path/to/ego-browser`；使用
`--no-start` 可只安装、不 bootstrap launch agent。安装器依次：

1. 严格校验 manifest 结构与 readiness 声明；
2. 按准确 release tag 校验 manifest 和 archive 的 Sigstore identity；
3. 校验 archive digest、inventory、路径和 runtime 兼容性；
4. 校验两个 macOS binary、Hardened Runtime 和 leaf certificate pin；
5. 安装到 `~/Library/Application Support/Agent Remote Ego Browser/releases/VERSION`；
6. 清除并复查 quarantine，再次校验已安装 release；
7. 写入受保护 certificate pin，原子切换 `current`，安装用户 launch agent。

## 注册与绑定

```sh
current="$HOME/Library/Application Support/Agent Remote Ego Browser/current"

"$current/bin/ego-browser-device" register \
  --server https://agent-remote.example.com \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

"$current/bin/ego-browser-device" candidates
"$current/bin/ego-browser-device" claim EXACT_TOOL_SESSION_ID --confirm
"$current/bin/ego-browser-device" status BINDING_ID
```

registration token 会作为首次操作的命令行输入，应使用短期 token。Device Client 不会在
输出中显示保存后的替换 credential 或 private key。claim 始终要求准确候选 session 和
显式全信任确认。Server 派生 `agent-remote:<tool_session_id>`；Device Client 会拒绝响应中
不同的 label，并把 canonical 值写入 owner-only active-binding handoff。resume 推进
generation 时会再次校验同一 label。

使用新的用户 token 原地轮换设备 signing key 与 encryption key：

```sh
"$current/bin/ego-browser-device" device-rotate \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm
```

轮换前应停止 active work。Device Client 保留 device ID，创建 generation `N+1`，在发送
任何请求前把新 key 写入仅所有者可访问的 `ego-browser-device-key.pending.bin`，并用该新
generation 对注册 PoP 签名。Server 接受新 key 时会原子撤销旧 binding 与 credential。
本机只提交准确匹配且 revision 更新的 Server 响应；提交会替换 key 与 credential、清除旧
active-binding handoff 并删除 pending file。若请求、响应或本地提交中断，请使用新的用户
token 重跑同一命令；pending file 会刻意复用完全相同的 generation 与 key，使操作收敛而
不会创建另一个身份。

## Helper allowlist 与 Site Learning

```sh
"$current/bin/ego-browser-device" allowlist show
"$current/bin/ego-browser-device" allowlist set /canonical/upload/root \
  --confirm --binding BINDING_ID --generation GENERATION

# 注册完成后且不使用 binding 级 CAS 时使用此形式。
"$current/bin/ego-browser-device" allowlist set /canonical/upload/root \
  --confirm --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

"$current/bin/ego-browser-device" learning verify
"$current/bin/ego-browser-device" learning set /absolute/signed/bundle \
  --confirm --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST
```

提供 binding 时，allowlist 更新会对当前 revision 执行 compare-and-swap。该形式与用户
token 形式互斥；Device Client 只有收到准确的 paused 响应和下一个 binding generation 后，
才提交本地 policy 并替换 handoff。

首次注册前，allowlist 与 learning 命令不带用户 token，仅配置本地 policy。注册完成后，
不采用 binding 级 allowlist CAS 的 policy 变更必须提供新的用户 registration token 和固定
的签名证书摘要。Device Client 使用同一 device identity 与 key generation 完成 new-key PoP
重新注册；Server 暂停所有 live binding、使旧 permit 失效，并签发 revision 更高的 credential。
响应中的所有版本、digest、capability、profile、证书、identity、key 与 generation 都必须
和提交值一致，随后客户端才清除 active handoff、提交 policy 并保存新 credential。本地提交
中断时，可使用另一个新用户 token 和同一命令重试。

learning bundle 必须只读、签名正确、hash 完整，并固定到 Skill `1.2.3` 与 runtime
`0.4.7.4`。

当前没有留存的 learning-bundle private key，无法签发生产 learning bundle，因此
`production_ready` 保持 false。

## 生命周期与诊断

```sh
"$current/bin/ego-browser-device" status BINDING_ID
"$current/bin/ego-browser-device" pause BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" resume BINDING_ID --generation GENERATION --confirm
"$current/bin/ego-browser-device" stop BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" revoke BINDING_ID --generation GENERATION
"$current/bin/ego-browser-device" device-revoke --confirm

launchctl print "gui/$(id -u)/dev.agentremote.ego-browser.device"
launchctl print "gui/$(id -u)/dev.agentremote.ego-browser.bridge"
tail -n 100 "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/bridge.log"
tail -n 100 "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/device.log"
```

远端使用 `ego-browser --doctor` 诊断。`ego-browser --reload` 只要求 Bridge 清理 runtime
连接状态，不会创建或重新授权 binding。日志刻意不包含脚本或浏览器正文。

Device Client 每 2 秒向 Bridge 发送固定 heartbeat。Bridge 会校验同 UID socket 与 peer、要求
首个 heartbeat，并把 5 秒内未收到有效 heartbeat 视为授权丢失。它先 revoke 本地执行，再
清除 active-binding handoff，最后最多用 10 秒尝试按 generation 停止 Server binding。stop
确认失败或超时不会恢复本地执行。

binding active 后，Bridge 还会运行一个独立 ownership monitor。它只读取 ego lite 原生
`listTaskSpaces()` ownership 数据，并在观察到 canonical 空间由 `agent` 持有后 armed；之后
出现 `agentDelegatedToUser` 或 `user` 时，先 revoke admission、终止受监管执行，再用
`task_space_takeover` 原因请求 generation-bound pause。monitor 意外故障按同一顺序使用
`task_space_monitor_unavailable`。该路径不依赖 helper exception 或脚本 stderr 解析，Bridge
也绝不会自动 claim/takeover。resume 必须由用户再次明确确认；只有用户决定交还控制后，才
使用 ego lite 原生 `takeOverTaskSpace('agent-remote:<tool_session_id>')` 工作流。若 pause 无法确认，
保持 Bridge 停止，并在任何新授权前检查 Server 状态。

## 指标与告警

Bridge 与 Device Client 日志中的 JSON metric event 是本地权威来源；本地不提供 Prometheus
endpoint。采集器必须从 launch-agent identity 添加可信 `component=bridge` 或
`component=device_client`，不能从不可信 event text 推导。

| 来源 | 指标 | 有限 label |
| --- | --- | --- |
| Bridge | `ego_browser_execute_total`、`ego_browser_execute_duration_seconds`、`ego_browser_bytes_total` | `status={completed,script_error,timeout,cancelled,bridge_unavailable,ego_runtime_unavailable,lease_expired,binding_revoked,protocol_error,artifact_error,concurrency_conflict,lease_renewal_required,unknown_result}`；bytes 另有 `direction={request,response}`。 |
| Bridge | `ego_browser_artifacts_total` | 同一 status，加 `media_type={image/png,image/jpeg,other}`。 |
| Device Client | `ego_browser_device_service_up` | `status={ready,stopped}`。 |
| Device Client | `ego_browser_device_bridge_peers` | `status={connected,disconnected}` 及当前 peer 数。 |
| Device Client | `ego_browser_device_peer_total` | `status=rejected`。 |
| Device Client | `ego_browser_device_refresh_total` | `status={completed,unregistered,identity_unavailable,client_unavailable,control_plane_error}`。 |

只检查可解析的 metric 行：

```sh
jq -R -c 'fromjson? | select(.event == "metric") |
  {metric,status,direction,media_type,value}' \
  "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/bridge.log"

jq -R -c 'fromjson? | select(.event == "metric") |
  {metric,status,value}' \
  "$HOME/Library/Application Support/Agent Remote Ego Browser/logs/device.log"
```

禁止把 user、device、tool session、binding、generation、request、URL、filename、本地路径、
脚本、页面、输入、输出或 artifact identifier 添加为 label。以下情况告警：任意
`unknown_result`；service-up 为零或缺失；active binding 期间 peer 异常下降；连续三次 metadata
refresh 失败（约 60 秒）；重复 lease/runtime 不可用；timeout、protocol、artifact 或 rejected
peer 比率异常。

## 跨仓库门禁

普通仓库门禁使用确定性 fake relay。强制的真实控制面 relay 门禁需要同级 Server/Node checkout
与一次性 Redis database：

```sh
AGENT_REMOTE_INTEGRATION_REDIS_URL=redis://127.0.0.1:6379/14 \
  bash integration-tests/real-relay-e2e.sh
```

该门禁启动真实 TLS Server WebSocket route、Redis ticket/pairing、Node broker、remote wrapper、
Device Client heartbeat service 与 outbound Bridge；只有最后的本地 `ego-browser` executable
是 fake。它证明三轮加密执行、ownership transition、接管后的外部终止、
`task_space_takeover` pause 与显式 resume generation、后续执行中 stop、descendant 终止、
replay ledger、已投递 outbox 与无正文指标。测试中的 helper error 被脚本捕获后会继续运行，
直到独立 ownership transition 将其停止。改变 release readiness 前还必须单独运行真实 ego
lite canary；两者不能互相替代。

## 恢复

- `bridge_unavailable`：必要时先注册本机设备，再列出候选并 claim 准确 session；不得创建
  临时或自动 binding。
- `lease_renewal_required` 或 `lease_expired`：停止旧 generation，检查 Server/Bridge，
  再用当前 generation 恢复，并重新确认 full trust。
- `binding_revoked`：重新显式 claim；已撤销 binding 不能恢复。
- `unknown_result`：先观察当前浏览器状态，再决定后续动作；绝不自动重放原 heredoc。
- runtime/version 不匹配：安装准确兼容版本；不得回退到远端浏览器、GUI 控制 channel 或
  原始网络 tunnel。
- 本地接管：确认 binding 为 `paused` 且 `stop_reason=task_space_takeover`，检查浏览器当前状态，
  显式 resume 返回的 generation，然后才使用 ego lite 原生 takeover helper 把 ownership 交还 agent；
  禁止重放被中断请求。
- `task_space_monitor_unavailable`：保持 admission 关闭，修复本地 runtime/Bridge service，检查
  浏览器当前状态与 Server generation 后再显式 resume；不得绕过 monitor 或伪造 ownership。
- relay 断开：受监管进程会被终止；只有确认浏览器当前状态后才能重连和恢复。
- Device Client heartbeat 丢失：保持本地 binding handoff 已清除，验证两个 launch agent 与
  Server outbox 已收敛，再创建新的显式 generation；不得复用旧 handoff 或 relay ticket。

日常 key 轮换应使用上述 `device-rotate`，不要撤销后重建设备。若整个设备已失陷或需要
退役，运行 `ego-browser-device device-revoke --confirm`，并仅在 Server 确认撤销后注册
新设备。签名证书轮换属于独立 release 操作，绝不隐式进行；改变本地 pin 前必须发布并
授权一个经过评审的双证书窗口。

## 卸载

```sh
"$current/installer/uninstall-macos.sh"
"$current/installer/uninstall-macos.sh" --remove-releases
"$current/installer/uninstall-macos.sh" \
  --remove-releases --purge-credentials --confirm-purge
```

默认只移除 launch agent 和 `current` link；删除凭据需要第二次显式确认。
`--remove-releases` 只移除 Bridge release tree。独立安装的 `ego-browser` executable、ego lite
及其 browser profile 均不受影响。
