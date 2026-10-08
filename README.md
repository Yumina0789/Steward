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
| 账户 | 账户列表、新增、改密码、删除、退出所有会话、账户事件流水 |

## 登录

**第一次打开**面板时它会让你**设置账户**（用户名 + 密码，密码至少 8 位）—— 那时还没有
账户，界面是「设置账户」而不是「登录」。之后就用这个账户登录，会话保持 7 天。

之后可以在「账户」页：加人、改密码（改谁的都行，但要用你自己当前的密码确认一次）、
删账户（最后一个删不掉）、退出自己的所有会话。同一 IP 5 分钟内错 8 次会临时被拒。

密码用 `scrypt` 加盐存，账户文件是数据目录下的 `accounts.json`（0600）。**忘了密码**就
删掉它再重启：`rm /var/lib/steward/accounts.json && systemctl restart steward`，回到首次设置。

**给机器留的凭证**：`/var/lib/steward/steward.token` 仍然能调整个 API（Steward 自己就拿
它去 Nimbus 拉限流决策，见 `docs/adr/0003`）。浏览器里从来不放这个 token。

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

## 挂在反向代理后面（可选）

面板默认只监听 `127.0.0.1`。如果反向代理跑在**容器**里（比如 Caddy/Nginx 的 compose），
它只能通过 docker 网桥的网关找到宿主机，所以要让面板多绑一份网桥地址：

```bash
sudo bash install.sh --bind 127.0.0.1,docker \
     --allow-ip 127.0.0.0/8,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
```

* `docker` 会在启动时现场查出宿主在 `docker0` / `br-*` 上的地址并一起监听 —— 网段变了
  也不用改配置。
* `--allow-ip` 是第二层：只有这些网段能访问，公网直连一律 403（绑了 `0.0.0.0` 时它才是关键）。
* 还要放行网桥到面板端口的流量，否则 ufw 会把反代的请求一起丢掉：

```bash
sudo ufw allow from 172.18.0.0/16 to any port 8402 proto tcp   # 网段按实际 compose 网络填
```

反向代理那边的站点块（以 Caddy 为例）：

```caddyfile
panel.example.com {
	encode zstd gzip
	reverse_proxy 172.18.0.1:8402      # 宿主在网桥上的地址
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options DENY
		Referrer-Policy "no-referrer"
		-Server
	}
}
```

代理会带上 `X-Forwarded-For`，面板在**直连方属于 `--allow-ip` 网段**时才会采信它，
所以审计日志里记的是真实客户端 IP，而不是那个容器的地址（伪造的头在网段外会被忽略）。

> 提醒：这样一来面板就在公网上了，token 是唯一的门。不想这样就把域名去掉、继续用
> SSH 隧道 —— 对一个能启停服务、杀进程、封 IP 的面板来说，隧道其实更合适。

## 本地预览

没在 Linux 上也能把界面看全 —— 演示模式用一份仿真的 /proc 数据，不碰真实系统：

```bash
python3 steward.py --mode demo --port 8402
```

## 参数

```
--mode demo|real     演示 / 真机（默认 real）
--bind IP            监听地址，默认 127.0.0.1。逗号分隔可绑多个；写 docker 会额外绑
                     一份宿主在 docker 网桥上的地址（反向代理在容器里时需要）
--allow-ip 网段       来源白名单（逗号分隔）；留空 = 不限制
--port N             默认 8402
--data-dir DIR       默认 /var/lib/steward（token 与审计日志）
--token-file PATH    默认 <data-dir>/steward.token
--token STR          直接指定 token，或用环境变量 STEWARD_TOKEN
--interval SEC       采样间隔，默认 2
--enforce-url U      从哪个面板拉「该封谁」（例如 http://127.0.0.1:8099 的 Nimbus）
--enforce-token T    上面那个面板的 token；给了才会开启自动封禁
--enforce-interval N 拉取间隔，默认 60 秒，0 = 关闭
```

自动封禁执行的仍然是 `ACTIONS` 表里的白名单动作（`ufw.deny` / `ufw.undeny`），
所以和手动封禁一样会写审计。

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
