# nos-monitor

Rust 实现的矿机监控与告警工具，支持本地日志监控和 SSH 集中监控，能够在以下场景触发告警：

- 挖矿/出块相关错误日志
- 节点存活检查失败（liveness）
- RPC 不可用或链高度停滞
- 远端主机不可达
- `screen` 会话缺失
- 进程缺失
- 日志时间戳长时间不推进（疑似卡死）并自动重启 miner 进程

## 功能特性

- 统一事件模型（`InputEvent -> AlertEvent`）
- 告警去重 + 冷却窗口控制
- Bark 推送（支持重试、超时）
- SSH 轮询远端 `screen` / 进程 / 日志
- 自动重启命令（`restart_command`）
- 日志停滞检测（`log_stale_threshold_secs`）

## 目录结构

- `src/main.rs`：程序入口，加载配置并启动各监控循环
- `src/config.rs`：配置模型、默认值与配置合并逻辑
- `src/ssh.rs`：SSH 集中监控、状态机、自动重启逻辑
- `src/detect/mod.rs`：事件映射与告警内容生成
- `src/alert/mod.rs`：告警发送（Bark）
- `src/dedup.rs`：去重与冷却
- `src/rpc.rs`：RPC 健康与链停滞检测
- `src/liveness.rs`：节点存活检测

## 构建

```bash
cargo build --release
```

产物：`target/release/nos-monitor`

## 运行

### 推荐（显式传入监控配置）

```bash
./target/release/nos-monitor -c monitor.yaml
```

### 同时指定基础配置（可选）

```bash
./target/release/nos-monitor -c monitor.yaml -f /root/nos/config.yaml
```

参数说明：

- `-c, --config`：监控配置文件（`monitor.yaml`）
- `-f, --base-config`：基础配置（默认尝试 `/root/nos/config.yaml`）

## monitor.yaml 示例

```yaml
monitor:
  node:
    server_addr: "NOS_NODE_IP:50051"

  logs:
    paths:
      - ./log/nos.log
    start_position: end

  detect:
    block_fail_keywords:
      - "出块失败"
      - "submit failed"
      - "invalid block"
    secondary_keywords:
      - "mine"
      - "block"
      - "submit"
    suppress_patterns:
      - "bind: address already in use"

  alert:
    bark_url: "https://api.day.app/替换你的key"
    bark_group: "groupName"
    dry_run: false
    dedup_window_secs: 900
    cooldown_secs: 300

  verify:
    enabled: true
    confirmations: 2
    backtrack_blocks: 2
    forward_blocks: 12
    pending_ttl_secs: 1800
    poll_interval_secs: 15

  liveness:
    interval_secs: 15
    timeout_ms: 1500
    failures_before_alert: 3
    successes_before_recovery: 2

  ssh:
    interval_secs: 15
    timeout_secs: 8
    tail_lines: 20
    restart_cooldown_secs: 300
    log_stale_threshold_secs: 120
    hosts:
      - name: "miner-1"
        host: "192.168.100.100"
        port: 22
        user: "boos"
        password: "boos."
        restart_command: "screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli_5.13"
      - name: "miner-2"
        host: "192.168.100.9"
        port: 22
        user: "boos"
        password: "boos."
        restart_command: "screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli_5.13"
```

## 爆块链上核验通知

- 打开 `monitor.verify.enabled: true` 后，程序会从日志提取 `workerID/height/nonce` 候选。
- 当链上确认到对应区块/证据时，会发送 `candidate_verified` 通知。
- 若在窗口时间内未确认，会发送 `candidate_unverified` 通知。

## 自动重启逻辑说明

- 当进程连续缺失达到阈值（内置阈值）会尝试执行 `restart_command`
- 当日志时间戳超过 `log_stale_threshold_secs` 不推进，也会尝试重启
- 两类重启都受 `restart_cooldown_secs` 控制
- 冷却期内不会重复重启，会发出 skipped cooldown 事件

## 常见事件

- `process_missing` / `process_recovered`
- `process_restart_triggered` / `process_restart_failed` / `process_restart_skipped_cooldown`
- `log_stale` / `log_recovered`
- `remote_host_down` / `remote_host_up`
- `screen_missing` / `screen_recovered`

## 调试建议

- 先开 `dry_run: true` 验证事件是否正确触发
- 检查远端是否能直接执行 `restart_command`
- 确认远端日志是 JSON 且包含 `timestamp` 字段（用于日志停滞检测）

## 测试

```bash
cargo test
```
