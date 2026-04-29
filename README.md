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
- 飞书 Webhook 推送（交互式卡片，支持重试、超时）
- SSH 轮询远端 `screen` / 进程 / 日志
- 自动重启命令（`restart_command`）
- 日志停滞检测（`log_stale_threshold_secs`）

## 目录结构

- `src/main.rs`：程序入口，加载配置并启动各监控循环
- `src/config.rs`：配置模型、默认值与配置合并逻辑
- `src/ssh.rs`：SSH 集中监控、状态机、自动重启逻辑
- `src/detect/mod.rs`：事件映射与告警内容生成
- `src/alert/mod.rs`：告警发送（飞书 Webhook）
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
./target/release/nos-monitor -c monitor.yaml -f ./config.yaml
```

参数说明：

- `-c, --config`：监控配置文件（`monitor.yaml`）
- `-f, --base-config`：基础配置（默认尝试 `$PWD/config.yaml`）

### 运行行为说明

- 程序会在当前工作目录下创建 `log/nos.log`，并将 tracing 日志同时写入该文件和标准输出。
- 若未传 `--base-config`，程序会尝试读取当前工作目录下的 `config.yaml`。
- 因此无论手动运行还是交给 systemd 托管，`WorkingDirectory` 都应与配置和日志目录规划保持一致。

## OpenRC 部署（更适合 Alpine）

如果你的机器用的是 **OpenRC**，优先用这一套。仓库里已经提供了服务脚本模板：`deploy/openrc/nos-monitor`。

### 1. 安装二进制

```bash
cargo build --release
sudo install -d /opt/nos-monitor
sudo install -m 0755 target/release/nos-monitor /opt/nos-monitor/nos-monitor
```

### 2. 准备配置

```bash
sudo install -d /etc/nos-monitor
sudo cp monitor.yaml /etc/nos-monitor/monitor.yaml
```

如果你还需要单独的基础配置文件，也可以额外放一个：

```bash
sudo cp config.yaml /etc/nos-monitor/config.yaml
```

OpenRC 默认脚本只带：

```sh
command_args="-c /etc/nos-monitor/monitor.yaml"
```

也就是 `config.yaml` 默认按 **可选项** 处理。

### 3. 安装 OpenRC 服务脚本

```bash
sudo install -D -m 0755 deploy/openrc/nos-monitor /etc/init.d/nos-monitor
```

默认脚本配置：

- 二进制：`/opt/nos-monitor/nos-monitor`
- 工作目录：`/opt/nos-monitor`
- 监控配置：`/etc/nos-monitor/monitor.yaml`
- 基础配置：默认不显式传入，按程序当前行为可选读取 `$PWD/config.yaml`
- 运行用户：`root`
- 日志目录：`/opt/nos-monitor/log`

如果你需要强制指定基础配置文件，就把脚本里的：

```sh
command_args="-c /etc/nos-monitor/monitor.yaml"
```

改成：

```sh
command_args="-c /etc/nos-monitor/monitor.yaml -f /etc/nos-monitor/config.yaml"
```

### 4. 加入开机启动并启动

```bash
sudo rc-update add nos-monitor default
sudo rc-service nos-monitor start
```

### 5. 常用运维命令

```bash
sudo rc-service nos-monitor status
sudo rc-service nos-monitor restart
sudo rc-service nos-monitor stop
```

### 6. 日志查看

OpenRC 脚本会把 stdout/stderr 分开落盘：

```bash
tail -f /opt/nos-monitor/log/stdout.log
tail -f /opt/nos-monitor/log/stderr.log
tail -f /opt/nos-monitor/log/nos.log
```

### 7. 注意事项

- 当前程序没有原生热加载；改完 YAML 后通常需要 `rc-service nos-monitor restart`
- `directory="/opt/nos-monitor"` 会影响程序默认的 `log/nos.log` 输出位置
- OpenRC 默认只传 `monitor.yaml`；如果你要显式使用 `/etc/nos-monitor/config.yaml`，请手动把 `-f` 加回 `command_args`
- OpenRC 脚本里用了 `checkpath`，启动前会自动确保 `/opt/nos-monitor/log` 存在
- 若后续改成非 root 用户运行，要同步调整 `/opt/nos-monitor` 和 `/etc/nos-monitor` 权限

## systemd 部署（兼容保留）

仓库提供了一个保守的 unit 模板：`deploy/systemd/nos-monitor@.service`。

该模板假定：

- 可执行文件位于 `/opt/nos-monitor/nos-monitor`
- 工作目录位于 `/opt/nos-monitor`
- 监控配置位于 `/etc/nos-monitor/monitor.yaml`
- 基础配置位于 `/etc/nos-monitor/config.yaml`
- 服务运行用户通过实例名传入，例如 `nos-monitor@root.service`

### 1. 安装二进制

```bash
cargo build --release
sudo install -d /opt/nos-monitor
sudo install -m 0755 target/release/nos-monitor /opt/nos-monitor/nos-monitor
```

### 2. 准备配置

```bash
sudo install -d /etc/nos-monitor
sudo cp monitor.yaml /etc/nos-monitor/monitor.yaml
sudo cp config.yaml /etc/nos-monitor/config.yaml
```

如果你没有单独的基础配置文件，也可以按当前 CLI 行为调整 unit，把 `-f /etc/nos-monitor/config.yaml` 去掉。

### 3. 安装 unit

```bash
sudo install -D -m 0644 deploy/systemd/nos-monitor@.service /etc/systemd/system/nos-monitor@.service
sudo systemctl daemon-reload
```

### 4. 启动服务

以 `root` 用户运行示例：

```bash
sudo systemctl enable --now nos-monitor@root
```

若希望以其他用户运行：

- 先确保该用户对 `/opt/nos-monitor` 和 `/etc/nos-monitor/*.yaml` 具有读取权限
- 确保 `/opt/nos-monitor/log` 可写
- 再启动对应实例，例如 `sudo systemctl enable --now nos-monitor@miner`

### 5. 常用运维命令

```bash
sudo systemctl status nos-monitor@root
sudo journalctl -u nos-monitor@root -f
sudo systemctl restart nos-monitor@root
sudo systemctl stop nos-monitor@root
```

### 6. 注意事项

- 当前程序没有原生 daemon/reload 配置热加载逻辑；修改 YAML 后通常需要 `systemctl restart`。
- 由于程序会写入 `WorkingDirectory/log/nos.log`，如果修改 `WorkingDirectory`，请同步调整目录权限。
- 模板使用了较保守的 hardening：`ProtectSystem=full`、`ProtectHome=true`、`PrivateTmp=true`。如果你的实际部署依赖 home 目录下的日志、二进制或额外文件，需要相应放宽。
- `Restart=on-failure` 只会在异常退出时自动拉起；正常停止不会自动重启。

## SSH 最常用写法（推荐）

如果你的机器大多是“同一批账号密码 + 同一重启命令 + 少数单机覆盖”，推荐直接按这个思路写：

```yaml
monitor:
  ssh:
    defaults:
      user: "boos"
      password: "boos."
      restart_command: "screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli_5.13"
      restart_cooldown_secs: 300

    ranges:
      - ips: "192.168.100.100-102"
      - ips: "192.168.101.10-11"
        user: "special-user"
        restart_command: "systemctl restart nos"

    hosts:
      - host: "192.168.100.9"
        name: "miner-1"
```

这也是当前最省事的写法：
- 统一配置放 `defaults`
- 成批机器放 `ranges`
- 个别特殊机器放 `hosts`

## monitor.yaml 完整示例

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
    feishu_webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/your-webhook-token"
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
    defaults:
      user: "boos"
      password: "boos."
      restart_command: "screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli_5.13"
      restart_cooldown_secs: 300
    ranges:
      - ips: "192.168.100.100-102"
      - ips: "192.168.101.10-11"
        user: "special-user"
        restart_command: "systemctl restart nos"
    hosts:
      - host: "192.168.100.9"
        name: "miner-1"
```

## SSH 共享默认值与 IP 范围展开

当前 SSH 配置支持两层：

- `monitor.ssh.defaults.*`：整组共享默认值
- `monitor.ssh.ranges[]`：按 IPv4 起止地址批量展开主机
- `monitor.ssh.hosts[]`：继续保留现有逐台配置方式

范围项当前支持两种写法：

- 简写：`ips: "192.168.100.100-102"`
- 兼容旧写法：`start` + `end`

范围项其他可选字段：

- `name_prefix`: 可选，展开后的名称格式为 `<name_prefix>-<最后一段IP>`
- 也可在 range 上直接设置 `user` / `password` / `restart_command` / `restart_cooldown_secs` / `node_addr` / `port`

优先级：

- 单台 `hosts[]` 自身字段优先于共享默认值
- `ranges[]` 会先展开成具体主机配置，然后与原有 `hosts[]` 一起走同一套后续默认值合并逻辑
- range 自身字段优先于共享默认值
- 若未设置 `name_prefix`：
  - 同一 `/24` 内范围会默认生成类似 `192-168-100-101` 这样的主机名
  - 跨 `/24` 范围会使用起始 IP 生成稳定前缀，例如从 `192.168.100.254` 到 `192.168.101.2` 会得到 `192-168-100-254-254`、`192-168-100-254-255`、`192-168-100-254-0`、`192-168-100-254-1`、`192-168-100-254-2`

示例：

```yaml
monitor:
  ssh:
    defaults:
      user: "boos"
      password: "boos."
      restart_command: "screen -S nos -X quit; cd ~ && screen -dmS nos ./nospowcli_5.13"
      restart_cooldown_secs: 300
    ranges:
      - ips: "192.168.100.100-105"
      - ips: "192.168.101.10-12"
        user: "special-user"
        restart_command: "systemctl restart nos"
    hosts:
      - host: "192.168.200.9"
        name: "special-box"
        user: "root"
```

推荐把共享 SSH 密码放到环境变量，而不是直接写进 YAML。

- 也可通过环境变量覆盖共享凭据：
  - `NOS_MONITOR_SSH_USER`
  - `NOS_MONITOR_SSH_PASSWORD`
- 若使用密码认证，程序通过 `SSHPASS` 环境变量传给 `sshpass`，避免把密码直接放进子进程参数列表
- 空字符串或仅空白的凭据/重启命令会被视为未配置，避免误把空值当作有效配置

示例：

```bash
export NOS_MONITOR_SSH_USER=boos
export NOS_MONITOR_SSH_PASSWORD='***'
./target/release/nos-monitor -c monitor.yaml
```

下一步再继续往你要的方向扩，就是：给一个 IP 范围，然后自动展开成多台主机，同时继续沿用这一套共享默认值。

## 飞书通知

- `alert.feishu_webhook_url` 配置为飞书机器人 Webhook 地址
- 告警会以交互式卡片发送，按严重级别使用不同颜色
- `dry_run: true` 时只打印事件，不实际发送通知

## 爆块链上核验通知

- 打开 `monitor.verify.enabled: true` 后，程序会从日志提取 `workerID/height/nonce` 候选。
- 当前支持中英文爆块日志关键字，以及 `workerID/worker_id`、`height/blockHeight/block_height` 等字段变体。
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
