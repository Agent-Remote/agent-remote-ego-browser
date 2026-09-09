# agent-remote-ego-browser

<p align="center"><img src="assets/agent-remote-icon.svg" alt="Agent Remote 图标" width="80" height="80"></p>

<p align="center">
  <a href="https://github.com/Agent-Remote/agent-remote-ego-browser/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Agent-Remote/agent-remote-ego-browser/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Agent-Remote/agent-remote-ego-browser/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Agent-Remote/agent-remote-ego-browser?style=flat&logo=github"></a>
  <img alt="Rust stable" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/github/license/Agent-Remote/agent-remote-ego-browser"></a>
</p>

[English](README.md) | 中文

本仓库把一个明确选择的远端 Agent Remote tool session，以本机全信任方式连接到用户 macOS 上已有的 ego lite 浏览器。

远端官方 `ego-browser` Skill 保持原有 heredoc 接口。Linux wrapper 经 Node 的 runtime 级 broker 和 Server 的 opaque relay，把每个请求发送到仅建立出站连接的本机 Bridge；Bridge 再使用用户真实的 ego lite profile 执行脚本。

## 发布状态

stable Bridge `0.1.7` release 已记录 `production_ready=true`、
`release_published=true`，且 `readiness_blockers=[]`。root composition 会独立固定其已认证的
准确 Bridge release。

该 stable GitHub release 已通过 `community-local-trust` 证据 profile，并包含由留存 key 签名的 Site Learning bundle；它仍为 `apple_notarized=false`、`public_distribution=false`。组件就绪不代表生产环境已经部署或完成 canary：在安装并验证准确的 root bundle、且真实 ego lite 单用户 canary 通过前，必须保持 `EGO_BROWSER_BRIDGE_ENABLED=false`。

## 安全警告

> 确认 binding 后，被选择的远端 session 将获得与 Bridge 所属 macOS 用户相同的本机全信任 Node.js 执行权限。它可以访问该用户的文件、环境、网络、浏览器 profile、登录状态、标签页、Task Space、dynamic import 和子进程 API，也可以把可访问的数据发送到其他位置。

无论远端 tool session 使用 `native` 还是 `docker_sandbox` backend，这一警告都完全适用。远端 runtime 的隔离不会 sandbox 已到达本机 Mac 的代码。专用 Task Space、helper 文件 allowlist、并发锁和进程监管都只是工作流与生命周期控制，不能回滚副作用，也不能约束刻意脱离监管的同 UID 进程。

生产 Bridge 不开放公网或 LAN listener。设备凭据、签名私钥、浏览器数据和明文脚本不会进入控制面；Server 只转发认证后的密文，并保存有界的生命周期、兼容性、policy 与审计元数据。

## 架构

```text
远端 ego-browser Skill
        |
        v
native 或 docker_sandbox 中的 Linux wrapper
        |
        v
Node runtime broker -> Server opaque WebSocket relay
        |                         |
        +-------------------------+
                                  v
                       出站 macOS Bridge
                                  |
                                  v
                     受监管的 ego-browser
                                  |
                                  v
                       本机 ego lite profile
```

| 组件 | 职责 |
| --- | --- |
| 远端 wrapper | 保持官方 heredoc CLI，校验有界输入，加密请求，并落盘有界 artifact。 |
| Node broker | 只允许已认证的 tool runtime。Native 使用专用 UID；Docker Sandbox 使用固定非 root runtime UID/GID，以及经过校验的 mount 和数字 ACL。 |
| Server relay | 配对准确 binding generation，并转发 opaque 加密 frame。 |
| Device Client | 独立负责注册、proof-of-possession key、显式 claim 确认、policy、轮换和撤销。 |
| 本机 Bridge | 维持出站 relay，校验 lease 与 policy，执行防重放与并发控制，并监管本机进程。 |
| ego lite | 保留真实浏览器 profile，并通过固定版本的本地 `ego-browser` runtime 执行。 |

每个请求使用 X25519 包装的 ChaCha20-Poly1305 session key。路由身份作为 associated data 被认证，relay sequence 会持久化以防重放；断线、撤销、lease 失败、Device Client peer 丢失或 Task Space ownership 变化都会 fail closed，未知结果不会重放。

## 兼容矩阵

| 范围 | 要求 |
| --- | --- |
| Bridge、Device Client、远端 wrapper | `0.1.7` |
| 协议 | `ego-browser-bridge-v1` |
| 官方 Skill | `1.2.3` |
| 本地 `ego-browser` runtime | `0.4.7.4` |
| 远端 runtime | Linux `native` 与 `docker_sandbox` |
| 远端 target | `amd64`/`arm64`，glibc/musl |
| 本机 target | macOS universal，`amd64` + `arm64` |

兼容条件必须准确匹配。未知、不完整或过期的 capability 会 fail closed；不会回退到远端浏览器、GUI control channel、raw CDP transport 或自动选择的 session。

## 安装

安装 stable `0.1.7` macOS release 时，必须同时使用 archive、严格 aggregate manifest、两个 Sigstore bundle，以及从独立可信渠道取得的 signing-certificate SHA-256：

```sh
./installer/install-macos.sh \
  --archive agent-remote-ego-browser-macos-universal-0.1.7.tar.gz \
  --archive-sigstore-bundle agent-remote-ego-browser-macos-universal-0.1.7.tar.gz.sigstore.json \
  --manifest agent-remote-ego-browser-0.1.7.release-manifest.json \
  --manifest-sigstore-bundle agent-remote-ego-browser-0.1.7.release-manifest.json.sigstore.json \
  --certificate-sha256 EXPECTED_64_HEX_DIGEST \
  --confirm-local-trust
```

安装器会校验 readiness claim、绑定 tag 的 Sigstore identity、artifact inventory 与 digest、嵌套代码签名、Hardened Runtime、leaf certificate、quarantine 状态和安装结果，全部通过后才原子切换 `current`。它不会安装、修改或删除 ego lite。

前置条件、注册、policy 设置、可观测性、恢复和卸载流程见[安装与运维](docs/operations.zh-CN.md)。

## 命令

注册独立 Device Client，并绑定一个准确的运行中 tool session：

```sh
ego-browser-device register \
  --server https://agent-remote.example.com \
  --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST

ego-browser-device candidates
ego-browser-device claim EXACT_TOOL_SESSION_ID --confirm
ego-browser-device status BINDING_ID
```

在该远端 session 中继续使用普通 wrapper 接口：

```sh
ego-browser <<'EOF'
const page = await useOrCreateTaskSpace('ignored-by-bound-session');
console.log(await page.snapshot());
EOF

ego-browser --doctor
ego-browser --reload
```

显式管理 binding 生命周期：

```sh
ego-browser-device pause BINDING_ID --generation GENERATION
ego-browser-device resume BINDING_ID --generation GENERATION --confirm
ego-browser-device stop BINDING_ID --generation GENERATION
ego-browser-device revoke BINDING_ID --generation GENERATION
ego-browser-device device-rotate --token USER_REGISTRATION_TOKEN \
  --signer-certificate-sha256 EXPECTED_64_HEX_DIGEST --confirm
ego-browser-device device-revoke --confirm
```

Policy 命令、Site Learning 校验和完整恢复流程见运维文档。任何流程都不依赖其他本地 device-control 产品。

## 开发

使用带 `rustfmt` 和 `clippy` 的 stable Rust toolchain。完整本地门禁包含格式检查、workspace clippy 与测试、Python 合同测试、release 与安装器检查、确定性的 fake-relay 集成测试、schema 校验和空白检查：

```sh
scripts/run-quality-checks.sh
```

只有在 sibling Server 和 Node 仓库可用且提供一次性 Redis 数据库时，才运行真实 distributed relay 证明：

```sh
AGENT_REMOTE_INTEGRATION_REDIS_URL=redis://127.0.0.1:6379/14 \
  bash integration-tests/real-relay-e2e.sh
```

该门禁使用真实 Server relay 和 Node broker，只有最后的本地 `ego-browser` executable 是 fixture。修改 release readiness 前仍必须单独执行真实 ego lite canary。

## 发布

准备本仓库负责的新版本并重新运行完整门禁：

```sh
scripts/prepare-release.sh NEXT_VERSION
scripts/run-quality-checks.sh
```

Prepare 脚本要求目标 semantic version 严格递增，并更新所有由本仓库负责的组件版本位置；协议、Skill、runtime、schema、依赖和 workflow action 的兼容版本保持不变。绑定 tag 的 workflow 会生成四个 Linux wrapper archive 和一个 macOS universal archive，并附带 checksum、Sigstore bundle、SPDX SBOM、provenance 和一个严格 aggregate manifest。

只有生成的 manifest 为 `production_ready=true` 且无 readiness blocker 时，workflow 才发布 stable release；否则发布 prerelease。`0.1.7` 已按 `community-local-trust` profile 通过组件门禁。剩余部署/canary 门禁与不可变 rollback 合同见[发布、升级与回滚](docs/release.zh-CN.md)。

## 文档

- [架构](docs/architecture.zh-CN.md)
- [安全模型](docs/security.zh-CN.md)
- [安装与运维](docs/operations.zh-CN.md)
- [发布、升级与回滚](docs/release.zh-CN.md)
- [示例](examples/README.md)

## 许可证

agent-remote-ego-browser 使用 GPL-3.0-only 许可证。详见 [LICENSE](LICENSE)。
