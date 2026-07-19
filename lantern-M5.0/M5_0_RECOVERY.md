# Lantern M5.0 恢复检查说明

日期：2026-07-19  
结论：**M5.0 已在先前检查点完成；本次未重跑 compatibility gate，只恢复最终源码并修复无界等待风险。**

## 1. 现场检查

| 检查项 | 结果 |
| --- | --- |
| 活动工作区源码 | `lantern/` 仅包含 M0；其 `target/` 也只保留 `lantern-types` 指纹 |
| Git | 工作区根 `.git` 是空占位目录；`git status`/`git log` 返回 `not a git repository`，不存在可核实的本地提交或远端 |
| 已有最终工件 | 找到 `lantern-m5.0.tar.gz`、`lantern-m5.0.sha256`、`M5_0_REPORT.md` 和 `M5_REQUIREMENTS.md` |
| 归档完整性 | 配套 `sha256sum -c` 通过；归档仅含单一 `lantern-m5.0/` 根且不含运行时秘密或构建目录 |
| 容器 | 当前环境没有可用的 Docker、Podman 或 Nerdctl 命令；无项目容器可检查或停止 |
| 残留进程 | 未发现 Cargo、Clippy、Rustc、Go、CometBFT、ABCI、下载、测试、`tail -f`、`watch` 或无限 `sleep` 进程 |
| 监听端口 | 仅观察到工作环境自身的回环监听；没有 M5 ABCI/CometBFT 端口 |

因此没有项目级无界等待进程需要发送 TERM/KILL，也没有前台服务需要迁移。

## 2. 最后一个成功步骤

最终报告及归档共同证明以下步骤已完成：

1. Go `ValidateBasic`/`VerifyCommit` 和四验证者 fixture 生成通过；
2. Rust `tendermint-rs` 0.40.4 对 header hash、validator-set hash、四组 sign bytes、Ed25519 签名和 LSB-first bitmap 验证通过；
3. 官方 `abci-cli` 的 `Info → FinalizeBlock → Commit → Info` loopback probe 通过；
4. M5.0 专项测试 4/4 通过；
5. 完整 workspace 回归 67/67 通过；
6. 完整 workspace Clippy `-D warnings` 通过；
7. RustSec、依赖许可清单、秘密扫描及可复现源码归档完成。

最后一个可信、成功完成的动作是第 7 步的源码归档。先前观察到的 Clippy 长时间构建并非最终失败；它在归档生成前已经完成。

## 3. 具体卡点

卡点由两部分组成：

- 活动 scratch 工作树没有保留 M1--M5.0 源码和 Git 元数据，只剩 M0，不能从该目录直接继续或查询提交历史；
- M5.0 编排脚本中，clone/build/generate/test/ABCI 请求和清理 `wait` 原先缺少统一超时，遇到网络、原生 RocksDB 构建或子进程不退出时会表现为无界等待。

这不是协议兼容、密码学验证或 ABCI wire probe 的失败。

## 4. 本次续作

- 从校验通过的最终归档恢复到独立目录，没有覆盖现存 M0 树；
- 为下载、构建、测试、fixture 生成、ABCI 请求、健康检查、日志读取、服务生命周期和退出清理加入显式超时；
- ABCI probe server 继续只在后台启动，并由有限生命周期监督；
- README 增加默认超时、覆盖变量和有界复现命令；
- 不启动服务、不下载依赖、不运行 compatibility gate，不把已有 PASS 结果伪装为本次新结果。

## 5. 本次验证边界

本次只允许不会重跑 M5.0 的检查：

- `sha256sum -c lantern-m5.0.sha256`；
- 四个 shell 脚本的 `bash -n`；
- 对脚本中下载、测试、健康检查、日志读取、服务和等待调用的静态扫描；
- 新归档路径安全、排除项和秘密模式扫描。

M5.1 仍需作者单独确认后才能开始。

## 6. 检查结果

- 原始持久化归档的配套 SHA-256 校验：PASS；
- `fetch-build-comet.sh`、`generate-reference.sh`、`run-abci-wire-probe.sh`、`run-gate.sh` 的 `bash -n`：PASS；
- 项目残留进程复查：0；
- M5 服务/请求/健康检查/日志读取/下载/测试路径的超时策略静态审查：PASS；
- 新归档的单根路径、目录排除、无符号链接和秘密模式扫描：PASS；
- 使用相同固定 UTC mtime、排序和 owner/group 参数二次打包，逐字节 `cmp`：PASS；
- M5.0 compatibility gate：本次未执行（沿用已完成检查点）。
