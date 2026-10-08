# Steward

单文件、零依赖的 Linux 服务器管理面板。只用 Python 3 标准库，装成宿主机上的一个
systemd 服务，默认只监听 `127.0.0.1`。

没有 Cockpit / 宝塔 / 1Panel 那些东西，是因为这台机器上需要看的东西很少，而多装一层
运行时本身就是负担。**必要功能，自己写。**

## 它能干什么

| 页面 | 内容 |
|---|---|
| 概览 | CPU / 内存 / 磁盘 / 网络 / 负载 / 进程数 / 运行时长，带实时曲线 |
| 服务 | systemd 单元列表、详情、日志，启停重启 |
| Docker | 容器列表（含 CPU/内存/网络）、镜像、日志，启停重启 |
| 安全 | 登录失败排行（按 IP / 用户名）、最近明细、ufw、fail2ban、SSH 配置摘要 |
| 端口 · 进程 | 监听端口（标出对外的）、已建立连接、占用最高的进程、发信号 |
| 日志 | journald 与 `/var/log` 下的文件 tail |
| 操作 · 审计 | 白名单动作清单 + 执行结果 + 审计记录 |

## 它**不**干什么

**没有 Web 终端。** 面板能改系统的全部手段就是 `steward.py` 里那张 `ACTIONS` 表：
每个动作一段写死的 argv、参数经过严格校验、以列表形式交给 `subprocess`（不过 shell），
危险动作界面二次确认，无论成败都写审计。理由写在 `docs/adr/0002`：把一个公网可达的
root shell 挂在 token 后面，风险与收益不成比例 —— 要敲命令就走 SSH。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/Yumina0789/Steward/main/install.sh | sudo bash
```

它会装到 `/opt/steward`、把 token 写进 `/var/lib/steward/steward.token`（600），
并启好 `steward.service`。升级就是重跑一遍（旧文件会留 `.bak`）。

从自己电脑访问，建议开隧道，一个端口都不用对外暴露：

```bash
ssh -L 8402:127.0.0.1:8402 root@<服务器 IP>
# 然后浏览器打开 http://127.0.0.1:8402/?token=<安装时打印的 token>
```

想用域名就交给反向代理（Caddy / Nginx），**不要**把监听改成 `0.0.0.0`：这是个能启停
服务、杀进程、封 IP 的 root 面板，公网上只有 token 一道门。

卸载：`bash install.sh --uninstall`（保留数据）或 `--purge`（连数据一起删）。

## 本地预览

没在 Linux 上也能把界面看全 —— 演示模式用一份仿真的 /proc 数据，不碰真实系统：

```bash
python3 steward.py --mode demo --port 8402
```

## 参数

```
--mode demo|real     演示 / 真机（默认 real）
--bind IP            默认 127.0.0.1
--port N             默认 8402
--data-dir DIR       默认 /var/lib/steward（token 与审计日志）
--token-file PATH    默认 <data-dir>/steward.token
--token STR          直接指定 token，或用环境变量 STEWARD_TOKEN
--interval SEC       采样间隔，默认 2
```

## 设计上的几条硬规矩

* **跑在宿主机，不进容器**：要管的就是宿主自己，容器化只会逼你交出 `docker.sock`
  和一堆特权挂载。见 `docs/adr/0001`。
* **不提供任意命令执行**：见上面与 `docs/adr/0002`。
* **观测数据不落库**：CPU / 网络靠 `/proc` 差值算，只留内存里的环形缓冲够画曲线。
  落盘的只有审计日志（超过 2 MB 轮转一份 `.1`）。2 vCPU / 2 GB 的小机器上也几乎无感。
* **不假装**：没有 systemctl、没有 docker、读不到 auth.log 时，界面如实说"不可用"，
  不编数据。

词汇表在 `CONTEXT.md`，决策记录在 `docs/adr/`。

## 自检

```bash
python3 tools/check.py     # 语法、界面里 id 与图标、安全底线
python3 tools/smoke.py     # 拉起演示实例，把所有接口打一遍
```

CI（`.github/workflows/ci.yml`）在 Python 3.8 / 3.11 / 3.13 上跑这两条，外加 shellcheck。

## 许可

MIT，见 `LICENSE`。
