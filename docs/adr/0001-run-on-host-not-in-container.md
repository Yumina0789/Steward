# 0001 面板跑在宿主机上，不是容器里

## 状态

已接受（2026-10-09）

## 背景

面板要管的是**托管机自己**：systemd 单元的启停、进程列表与结束进程、`/var/log` 与 journald、监听端口、防火墙规则。这些全都是宿主机的命名空间里的东西。

我们刚在 Nimbus 上验证过容器化面板（挂宿主 `/etc/vlmcsd`、用 supervisord 代替 systemd、通过 unix socket 调 supervisor 的 XML-RPC）。那套做法在「管一个容器里的守护进程」时是合适的，但换成「管整台机器」就会要求：

- `privileged` 或至少 `--pid=host` + `--network=host`；
- 挂载宿主 `/proc`、`/sys`、`/var/log`、`/etc/systemd`；
- 挂 `docker.sock`（等于交出宿主 root）；
- systemd 相关的操作要退化成 `nsenter` 或 `systemctl --host`。

也就是说：为了容器化，得先把容器的隔离墙拆掉，再把面板能碰到的宿主路径一个个挂进来。

## 决策

Steward 是一个**单文件 Python 标准库程序**，装成宿主机上的 `steward.service`（`Type=simple`，`Restart=always`），默认只监听 `127.0.0.1:8402`，对外通过反向代理接入。

## 后果

- 好的一面：直接读写宿主 `/proc`、调 `systemctl`/`journalctl`/`docker`，不需要任何特权标志或额外挂载；不引入任何依赖（宿主 Python 3.8 就够，实测 Ubuntu 20.04 自带），因此在 2 vCPU / 2 GB 的小机器上几乎没有成本。
- 差的一面：**没有容器隔离**。面板进程本身就是 root，它一旦被攻破就等于机器被攻破。这也是为什么它默认只监听回环、只提供白名单动作（见 0002），并且每次改状态都写审计。
- 升级方式变成「换文件 + `systemctl restart steward`」，没有镜像可回滚 —— 所以安装脚本会保留上一份副本。

## 备选方案

1. **做成 Nimbus 的一个标签页**：最省资源、只有一个面板要维护。否决原因：Nimbus 在容器里，管不到宿主 systemd/进程/文件，那正是这个面板存在的意义；而且两者职责与故障域完全不同（KMS 面板挂了不该影响运维入口）。
2. **独立容器 + `privileged` + `docker.sock`**：能跑，但等于把宿主 root 通过 socket 暴露给一个 Web 面板，隔离形同虚设，却还要为此维护镜像与挂载清单。收益为负。
