# 发布、升级与回滚

## 证据 profile

release `0.1.3` 的目标为 `community-local-trust`：

| 声明 | 必须值 |
| --- | --- |
| Signing | `project-self-signed` |
| Hardened Runtime | `true` |
| Nested signatures verified | `true` |
| Outbound policy | `application-enforced` |
| Credential profile | `community_file` |
| Apple notarized | `false` |
| Public distribution | `false` |
| Production ready | `false` |
| Learning bundle digest | `null` |
| Readiness blocker | `learning_bundle_signing_private_key_unavailable` |

持久项目证书及其 SHA-256 是 CI environment 输入，不会在每次构建时重新生成。GitHub
Actions 使用绑定到 `release.yml@refs/tags/vVERSION` 的 keyless Sigstore identity 对
release asset 签名，发布 SPDX SBOM 与 provenance attestation；readiness 为 false 时，
release 必须标记为 prerelease。

## 准备发布

```sh
scripts/prepare-release.sh NEXT_VERSION
scripts/run-quality-checks.sh
```

prepare 脚本要求目标 semantic version 严格递增。它会更新 workspace version、
`Cargo.lock` 中所有本仓库 package entry、`VERSION`、协议 capability vector，以及本仓库
负责的全部中英文兼容矩阵和安装示例。脚本会在写入前拒绝过期 source value 与已有 changelog
heading，添加带日期的 changelog entry，保持依赖、schema、Skill、runtime 和 workflow action
版本不变，最后执行 locked workspace 校验。正式 workflow 提交这些文件、创建不可变
`vVERSION` tag，再 dispatch 与 tag 绑定的 release workflow。

release 产生四个 Linux wrapper archive 与一个 universal macOS 本地组件 archive。每个
artifact 都有 checksum、Sigstore bundle、SPDX SBOM 和 provenance。聚合 strict release
manifest 固定其准确文件名、大小、digest、版本、平台、release 声明和签名证书。

## 升级

1. 未完成兼容 canary 时先禁止新 claim。
2. 先发布并校验新的 Server 与 Node release。
3. 安装同一兼容矩阵行中的不可变 Node wrapper/Skill 组合。
4. 下载 macOS archive、聚合 manifest 以及两者的 Sigstore bundle。
5. 从独立可信渠道确认预期 certificate digest。
6. 运行 `install-macos.sh`；它保留旧 release 目录，全部校验通过后才原子切换 `current`。
7. 重启后的 launch agent 会等待注册与显式 binding，不会 crash-loop 或自动绑定。
8. 再次确认 full trust，创建新 generation，运行 `--doctor` 和单用户 canary；不重放旧
   permit 或 request。

兼容版本是准确约束：wrapper/Bridge/Device Client `0.1.3`、协议
`ego-browser-bridge-v1`、Skill `1.2.3`、本地 runtime `0.4.7.4`。未知或不完整 capability
均 fail closed，且不存在浏览器或 transport fallback。

## 回滚

先在控制面禁用新 browser claim，撤销 active binding，等待最多 10 秒续期失败宽限及
受监管进程清理，并确认 Node broker 没有 active permit。然后在 Mac 执行：

```sh
current="$HOME/Library/Application Support/Agent Remote Ego Browser/current"
"$current/installer/rollback-macos.sh" PREVIOUS_VERSION
```

rollback 会用受保护 certificate pin 校验目标 release，并在切换 `current` 前校验两个已
安装 launch-agent definition，随后 bootstrap 两个 agent。选中的 release 不继承旧 relay
ticket、generation 或 request；用户必须重新显式授权。保留终态 binding 和 audit metadata，
不执行 destructive schema downgrade。

如果新 release 更换签名证书，标准安装器会拒绝隐式 rotation。证书变更要求经过评审的
双证书控制面窗口、本地显式信任、新签名 manifest、旧 pin 撤销以及新 binding generation。

## 生产阻塞项

在留存且受保护的 Site Learning 签名 key 签发固定 bundle、manifest 可以携带非 null 且
已验证的 digest 之前，不得把 `production_ready` 改为 true，不得开启 Server 生产
capability，也不得称该 package 已生产就绪。当前不存在这样的 private key。
