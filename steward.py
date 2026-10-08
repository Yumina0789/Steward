#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
steward —— 单文件、零依赖的 Linux 服务器管理面板（Python 3 标准库，不需要 pip）

管的是什么
----------
**托管机自己**：systemd 服务、Docker 容器、进程与监听端口、日志、安全面（登录失败、
防火墙、fail2ban）。所以它装成宿主上的 systemd 服务而不是容器（见 docs/adr/0001）。

两条硬规矩
----------
* **不提供任意命令执行**。只有代码里写死的白名单动作，参数以列表形式交给
  subprocess，不经过 shell；危险动作界面二次确认 + 无论成败都写审计（见 docs/adr/0002）。
* 观测数据只活在内存里（环形缓冲够画曲线就行，不落库），落盘的只有审计日志。

用法
----
    python3 steward.py --mode demo --port 8402
    python3 steward.py --mode real --bind 127.0.0.1 --port 8402 \\
                       --data-dir /var/lib/steward --token-file /var/lib/steward/steward.token

安全
----
默认只绑 127.0.0.1；所有 /api/* 都要 token；token 文件 600。面板进程是 root ——
它就是半个 root shell，别裸奔在公网。
"""

import argparse
import base64
import collections
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

VERSION = "0.1.0"
HERE = Path(__file__).resolve().parent

# 真实文件系统才列进磁盘面板；overlay/tmpfs 那些是容器与内存的，列出来只会干扰
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "vfat"}
# 单元名与容器名的白名单形状：systemd 与 docker 都只认这套字符，先挡住注入
NAME_RE = re.compile(r"^[A-Za-z0-9_.@:\\-]{1,128}$")
# 允许 tail 的日志文件：必须落在这些目录下，且不含 ..（真实路径还要再校验一次）
LOG_DIRS = ("/var/log/", "/var/lib/steward/")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:\\-]{1,128}$")


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%.0f %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def dur_text(sec):
    sec = int(sec or 0)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    if d:
        return "%d 天 %d 小时" % (d, h)
    if h:
        return "%d 小时 %d 分" % (h, m)
    return "%d 分" % m


def run(argv, timeout=15, cwd=None):
    """跑一条命令。argv 是列表，绝不经过 shell。

    返回 (返回码, stdout, stderr)。命令不存在/超时都不抛异常，返回码用负数表达：
    -1 = 起不来（缺命令），-2 = 超时。
    """
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return -1, "", "找不到命令：%s" % argv[0]
    except subprocess.TimeoutExpired:
        return -2, "", "命令超时（%ss）：%s" % (timeout, " ".join(argv))
    except (OSError, subprocess.SubprocessError) as e:  # noqa: BLE001
        return -3, "", "%s: %s" % (type(e).__name__, e)


def read_text(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit) if limit else fh.read()
    except OSError:
        return ""


def same_secret(a, b):
    """定时安全比较。

    compare_digest 只吃 ASCII 的 str，碰上非 ASCII 会抛 TypeError —— 而 token 是
    用户输入，随手发个中文就能把请求处理线程打崩（连接直接断，连 403 都回不去）。
    统一编码成 bytes 再比。
    """
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def docker_bridge_addresses():
    """宿主在 docker 网桥上的地址（docker0 与 br-*）。

    反向代理通常跑在容器里，只能通过网桥网关找宿主 —— 所以面板除了回环，还得在这
    个地址上听一份。用 ip 命令现场问，网段变了也不怕。
    """
    code, out, _ = run(["ip", "-4", "-o", "addr", "show"], timeout=10)
    addrs = []
    for line in out.splitlines():
        f = line.split()
        if len(f) > 3 and f[2] == "inet" and (f[1].startswith("br-") or f[1] == "docker0"):
            addrs.append(f[3].split("/")[0])
    return addrs


def expand_binds(spec):
    """--bind 支持逗号分隔的多个地址；其中 "docker" 展开成上面的网桥地址。"""
    out = []
    for part in str(spec or "127.0.0.1").split(","):
        part = part.strip()
        if not part:
            continue
        if part == "docker":
            out += docker_bridge_addresses()
        else:
            out.append(part)
    uniq = []
    for a in out:
        if a not in uniq:
            uniq.append(a)
    return uniq or ["127.0.0.1"]


def parse_networks(text):
    import ipaddress
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


def parse_skip(text):
    """限流永不封禁的网段（默认回环 + 内网）。"""
    return parse_networks(text)


# --------------------------------------------------------------------------
# 账户：第一次进来先设一个，之后用户名 + 密码登录
# --------------------------------------------------------------------------
PASSWORD_MIN = 8
SESSION_TTL = 7 * 86400          # 登录态保持 7 天，过期要重新登录
LOGIN_WINDOW = 300               # 登录失败的统计窗口（秒）
LOGIN_MAX_FAIL = 8               # 窗口内失败超过这个数就封
# 递增封禁：第一次 5 分钟，再犯 30 分钟，第三次起 6 小时。
# 24 小时内没再犯就降回第一档；成功登录直接清零 —— 正常用户打错几次密码不会把自己
# 越封越久，而持续爆破的家伙会一路封到 6 小时。
LOGIN_BLOCK_TIERS = (300, 1800, 21600)
LOGIN_FORGET = 86400
USER_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password, salt=None):
    """把密码存成可校验的字符串。

    优先 scrypt（标准库自带、内存硬，比单纯迭代 sha256 抗显卡爆破）；万一这个 Python
    没编进 scrypt，退回 pbkdf2。算法与参数都写在字符串里，所以将来调参也不会认不出老密码。
    """
    salt = salt or os.urandom(16)
    raw = password.encode("utf-8")
    if hasattr(hashlib, "scrypt"):
        n, r, p = 1 << 14, 8, 1
        dk = hashlib.scrypt(raw, salt=salt, n=n, r=r, p=p, dklen=32)
        return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(dk))
    iters = 200000
    dk = hashlib.pbkdf2_hmac("sha256", raw, salt, iters, dklen=32)
    return "pbkdf2$%d$%s$%s" % (iters, _b64(salt), _b64(dk))


def verify_password(password, stored):
    try:
        parts = (stored or "").split("$")
        raw = password.encode("utf-8")
        if parts[0] == "scrypt" and len(parts) == 6:
            _, n, r, p, salt_b64, want_b64 = parts
            salt, want = base64.b64decode(salt_b64), base64.b64decode(want_b64)
            got = hashlib.scrypt(raw, salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(want))
        elif parts[0] == "pbkdf2" and len(parts) == 4:
            _, iters, salt_b64, want_b64 = parts
            salt, want = base64.b64decode(salt_b64), base64.b64decode(want_b64)
            got = hashlib.pbkdf2_hmac("sha256", raw, salt, int(iters), dklen=len(want))
        else:
            return False
        return same_secret(got.hex(), want.hex())
    except (ValueError, TypeError, IndexError):
        return False


class LoginGuard:
    """登录失败的摩擦：同一来源在窗口内错太多次就封，而且**一次比一次久**。

    * 只按来源 IP 算，不按账户 —— 攻击者没法把你锁在门外，你打错密码也不连累自己。
    * 状态落盘到 loginguard.json（0600）：重启面板不该等于替攻击者清空记录。
    * 成功登录清零；24 小时没再犯也降回第一档。所以只有"持续爆破"才会被封到 6 小时。
    """

    def __init__(self, path=None, window=LOGIN_WINDOW, limit=LOGIN_MAX_FAIL,
                 tiers=LOGIN_BLOCK_TIERS, forget=LOGIN_FORGET):
        self.path = Path(path) if path else None
        self.window, self.limit, self.tiers, self.forget = window, limit, tiers, forget
        self.lock = threading.Lock()
        self.state = {"ips": {}}      # ip -> {fails: [ts], blocked_until, level, last}
        self._load()

    # --- 落盘 -------------------------------------------------------------
    def _load(self):
        if not self.path:
            return
        try:
            if self.path.exists():
                d = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(d, dict) and isinstance(d.get("ips"), dict):
                    self.state = d
        except (OSError, ValueError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            tmp = Path(str(self.path) + ".tmp")
            tmp.write_text(json.dumps(self.state, ensure_ascii=False), encoding="utf-8")
            os.chmod(str(tmp), 0o600)
            os.replace(str(tmp), str(self.path))
        except OSError:
            pass

    # --- 判定 -------------------------------------------------------------
    def _entry(self, ip):
        e = self.state["ips"].get(ip)
        if not isinstance(e, dict):
            e = {"fails": [], "blocked_until": 0, "level": 0, "last": 0}
            self.state["ips"][ip] = e
        return e

    def wait_seconds(self, ip):
        """还要等多少秒才能再试；0 = 现在可以试。"""
        now = time.time()
        with self.lock:
            e = self._entry(ip)
            until = float(e.get("blocked_until") or 0)
            if until > now:
                return int(until - now) + 1
            e["blocked_until"] = 0
            e["fails"] = [t for t in (e.get("fails") or []) if now - t < self.window]
            if e.get("last") and now - e["last"] > self.forget:
                e["level"] = 0                                      # 很久没犯，档位降回去
            return 0

    def fail(self, ip):
        """记一次失败。返回 (是否被封, 封多久秒, 第几档)。"""
        now = time.time()
        with self.lock:
            e = self._entry(ip)
            hits = [t for t in (e.get("fails") or []) if now - t < self.window]
            hits.append(now)
            e["fails"] = hits
            e["last"] = now
            blocked, secs = False, 0
            if len(hits) >= self.limit:
                e["level"] = min(int(e.get("level") or 0) + 1, len(self.tiers))
                secs = self.tiers[e["level"] - 1]
                e["blocked_until"] = now + secs
                e["fails"] = []
                blocked = True
            self._prune(now)
            self._save()
            return blocked, secs, int(e.get("level") or 0)

    def ok(self, ip):
        """登录成功：这个来源的记录整个清掉。"""
        with self.lock:
            if self.state["ips"].pop(ip, None):
                self._save()

    def unblock(self, ip):
        """人工解封：放行这个来源，但**保留档位**——解封不等于给攻击者重置计数。"""
        with self.lock:
            e = self.state["ips"].get(ip)
            if not isinstance(e, dict):
                return False
            was = float(e.get("blocked_until") or 0) > time.time()
            e["blocked_until"] = 0
            e["fails"] = []
            if was:
                self._save()
            return was

    def _prune(self, now):
        """别让文件无限长：很久没动静、又没在封禁中的来源直接忘掉。"""
        for k in [k for k, v in self.state["ips"].items()
                  if isinstance(v, dict) and now - float(v.get("last") or 0) > self.forget * 7
                  and float(v.get("blocked_until") or 0) < now]:
            self.state["ips"].pop(k, None)

    def status(self, limit=20):
        now = time.time()
        rows = []
        with self.lock:
            for ip, e in self.state["ips"].items():
                if not isinstance(e, dict):
                    continue
                until = float(e.get("blocked_until") or 0)
                if until > now:
                    rows.append({"ip": ip, "seconds": int(until - now),
                                 "level": int(e.get("level") or 0),
                                 "fails": len(e.get("fails") or [])})
        rows.sort(key=lambda r: -r["seconds"])
        return {"blocked": rows[:limit], "tracked": len(self.state["ips"]),
                "tiers": [int(t) for t in self.tiers], "limit": self.limit,
                "window": self.window}


class Accounts:
    """账户与会话，存一个 0600 的 JSON 文件。

    不用数据库：这台机器上就一两个人的账户，几十行 JSON 足够；而且万一忘了密码，
    运维直接看文件就能明白结构、删掉重建。
    """

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data = {"users": {}, "sessions": {}}
        self._load()

    # --- 读写 -------------------------------------------------------------
    def _load(self):
        try:
            if self.path.exists():
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
                self.data.setdefault("users", {})
                self.data.setdefault("sessions", {})
        except (OSError, ValueError):
            self.data = {"users": {}, "sessions": {}}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(str(self.path) + ".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.chmod(str(tmp), 0o600)
            os.replace(str(tmp), str(self.path))
        except OSError:
            pass

    # --- 账户 -------------------------------------------------------------
    def need_setup(self):
        with self.lock:
            return not self.data["users"]

    def names(self):
        with self.lock:
            return sorted(self.data["users"])

    def create(self, name, password):
        name = (name or "").strip()
        if not USER_RE.match(name):
            return False, "用户名只能 2~32 位字母、数字、下划线、点或横线"
        if len(password or "") < PASSWORD_MIN:
            return False, "密码至少 %d 位" % PASSWORD_MIN
        with self.lock:
            if name in self.data["users"]:
                return False, "这个用户名已经有了"
            self.data["users"][name] = {"hash": hash_password(password),
                                        "created": int(time.time()), "last_login": 0}
            self._save()
        return True, ""

    def set_password(self, name, password):
        if len(password or "") < PASSWORD_MIN:
            return False, "密码至少 %d 位" % PASSWORD_MIN
        with self.lock:
            u = self.data["users"].get(name)
            if not u:
                return False, "没有这个账户"
            u["hash"] = hash_password(password)
            self._save()
        return True, ""

    def delete(self, name):
        with self.lock:
            if name not in self.data["users"]:
                return False, "没有这个账户"
            if len(self.data["users"]) <= 1:
                return False, "这是最后一个账户，删了就没人能登录了"
            self.data["users"].pop(name)
            for tok in [t for t, s in self.data["sessions"].items() if s.get("user") == name]:
                self.data["sessions"].pop(tok, None)
            self._save()
        return True, ""

    def check(self, name, password):
        with self.lock:
            u = self.data["users"].get((name or "").strip())
        if not u:
            # 不存在也照样算一次哈希，别让响应时间暴露"这个用户名存在"
            verify_password(password or "", hash_password("dummy-password"))
            return False
        return verify_password(password or "", u["hash"])

    def touch_login(self, name):
        with self.lock:
            if name in self.data["users"]:
                self.data["users"][name]["last_login"] = int(time.time())
                self._save()

    def listing(self):
        with self.lock:
            sessions = collections.Counter(s.get("user") for s in self.data["sessions"].values())
            return [{"name": n, "created": u.get("created", 0), "last_login": u.get("last_login", 0),
                     "sessions": sessions.get(n, 0)}
                    for n, u in sorted(self.data["users"].items())]

    # --- 会话 -------------------------------------------------------------
    def new_session(self, name, ttl=SESSION_TTL):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.prune_locked()
            self.data["sessions"][tok] = {"user": name, "created": int(time.time()),
                                          "expires": int(time.time()) + ttl}
            self._save()
        return tok

    def session_user(self, token):
        if not token:
            return ""
        with self.lock:
            s = self.data["sessions"].get(token)
            if not s:
                return ""
            if s.get("expires", 0) < time.time():
                self.data["sessions"].pop(token, None)
                self._save()
                return ""
            return s.get("user", "")

    def drop_session(self, token):
        with self.lock:
            if self.data["sessions"].pop(token, None):
                self._save()

    def drop_user_sessions(self, name):
        with self.lock:
            victims = [t for t, s in self.data["sessions"].items() if s.get("user") == name]
            for t in victims:
                self.data["sessions"].pop(t, None)
            if victims:
                self._save()
        return len(victims)

    def prune_locked(self):
        now = time.time()
        for t in [t for t, s in self.data["sessions"].items() if s.get("expires", 0) < now]:
            self.data["sessions"].pop(t, None)


# --------------------------------------------------------------------------
# 采样：CPU / 内存 / 网络 / 磁盘 / 负载。全部来自 /proc 与 statvfs，不落库
# --------------------------------------------------------------------------
class Sampler:
    """每隔 interval 秒读一次 /proc，算出 CPU 使用率与网络速率存进环形缓冲。"""

    def __init__(self, interval=2.0, keep=90, fake=False):
        self.interval = interval
        self.fake = fake          # 演示模式：即使有 /proc 也用仿真数据，保证演示可复现
        self.samples = collections.deque(maxlen=keep)
        self.lock = threading.Lock()
        self._prev_cpu = None
        self._prev_net = None
        self._stopped = False

    # --- /proc 解析 -------------------------------------------------------
    @staticmethod
    def _read_cpu():
        """返回 (总 jiffies, 空闲 jiffies, [每核 (总, 空闲)])。"""
        text = read_text("/proc/stat")
        total = idle = 0
        cores = []
        for line in text.splitlines():
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            if parts[0] == "cpu":
                nums = [int(x) for x in parts[1:]]
                # idle + iowait 算空闲；guest 时间已经包含在 user/nice 里，不再重复计
                total = sum(nums[:8])
                idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
            elif parts[0][3:].isdigit():
                nums = [int(x) for x in parts[1:]]
                cores.append((sum(nums[:8]), nums[3] + (nums[4] if len(nums) > 4 else 0)))
        return total, idle, cores

    @staticmethod
    def _read_net():
        """返回 (rx_bytes, tx_bytes)，lo 不算。"""
        rx = tx = 0
        for line in read_text("/proc/net/dev").splitlines()[2:]:
            if ":" not in line:
                continue
            iface, rest = line.split(":", 1)
            if iface.strip() == "lo":
                continue
            f = rest.split()
            if len(f) >= 9:
                rx += int(f[0])
                tx += int(f[8])
        return rx, tx

    @staticmethod
    def _read_mem():
        info = {}
        for line in read_text("/proc/meminfo").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            num = v.strip().split()[0] if v.strip() else "0"
            info[k] = int(num) * 1024 if num.isdigit() else 0
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = max(0, total - avail)
        st, sf = info.get("SwapTotal", 0), info.get("SwapFree", 0)
        return {"total": total, "used": used, "available": avail,
                "free": info.get("MemFree", 0), "buffers": info.get("Buffers", 0),
                "cached": info.get("Cached", 0), "percent": (used / total * 100) if total else 0,
                "swap_total": st, "swap_used": max(0, st - sf),
                "swap_percent": ((st - sf) / st * 100) if st else 0}

    @staticmethod
    def _read_disk():
        """一个 (设备, 文件系统) 只留一条。

        真机上 /、/etc、/home、/root 常常是同一个分区的 bind mount，全列出来只是
        把同一个数字重复八遍。取挂载路径最短的那个（通常是 /）。
        """
        out = {}
        for line in read_text("/proc/mounts").splitlines():
            f = line.split()
            if len(f) < 3:
                continue
            dev, mount, fstype = f[0], f[1].replace("\\040", " "), f[2]
            if fstype not in REAL_FS or not dev.startswith("/dev/"):
                continue
            try:
                st = os.statvfs(mount)
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            if not total:
                continue
            free = st.f_bavail * st.f_frsize
            used = total - st.f_bfree * st.f_frsize
            inodes = st.f_files
            entry = {
                "mount": mount, "device": dev, "fstype": fstype,
                "total": total, "used": used, "free": free,
                "percent": (used / total * 100) if total else 0,
                "inodes_total": inodes,
                "inodes_percent": ((inodes - st.f_ffree) / inodes * 100) if inodes else 0,
            }
            key = (dev, fstype)
            old = out.get(key)
            if old is None or len(mount) < len(old["mount"]):
                out[key] = entry
        return sorted(out.values(), key=lambda d: -d["total"])

    @staticmethod
    def _read_proc_count():
        n = 0
        try:
            for name in os.listdir("/proc"):
                if name.isdigit():
                    n += 1
        except OSError:
            pass
        return n

    @staticmethod
    def _read_uptime():
        try:
            return float(read_text("/proc/uptime").split()[0])
        except (IndexError, ValueError):
            return 0.0

    # --- 采样循环 ---------------------------------------------------------
    def _fake_snapshot(self):
        """没有 /proc（比如在 Windows 上跑演示）时给一组仿真的数，别让界面全是 0。"""
        self._fake_n = getattr(self, "_fake_n", 0) + 1
        wave = (math.sin(self._fake_n / 5.0) + 1) / 2.0
        cpu = round(9 + wave * 52, 1)
        t = time.time()
        self._fake_rx = getattr(self, "_fake_rx", 1.2e9) + 40_000 + wave * 700_000
        self._fake_tx = getattr(self, "_fake_tx", 0.4e9) + 18_000 + wave * 240_000
        total = 2 << 30
        used = int(total * (0.44 + wave * 0.16))
        return {
            "t": t, "ts": now_iso(),
            "cpu": cpu, "cores": [round(max(1.0, cpu + ((i * 17) % 13) - 6), 1) for i in range(4)],
            "cpu_count": 4, "load": [round(0.3 + wave * 1.4, 2), round(0.2 + wave, 2), 0.15],
            "mem": {"total": total, "used": used, "available": total - used,
                    "free": total - used, "buffers": 60 << 20, "cached": 700 << 20,
                    "percent": used / total * 100, "swap_total": 0, "swap_used": 0,
                    "swap_percent": 0.0},
            "disk": [{"mount": "/", "device": "/dev/vda1", "fstype": "ext4",
                      "total": 30 << 30, "used": 8 << 30, "free": 22 << 30,
                      "percent": 27.0, "inodes_total": 2000000, "inodes_percent": 12.0},
                     {"mount": "/data", "device": "/dev/vdb1", "fstype": "ext4",
                      "total": 100 << 30, "used": 63 << 30, "free": 37 << 30,
                      "percent": 63.0, "inodes_total": 6000000, "inodes_percent": 41.0}],
            "procs": {"total": 138, "zombie": 1, "running": 3},
            "uptime": 2_600_000 + self._fake_n,
            "rx_total": int(self._fake_rx), "tx_total": int(self._fake_tx),
            "rx_bps": 40_000 + wave * 700_000, "tx_bps": 18_000 + wave * 240_000,
        }

    def _snapshot(self):
        if self.fake or not os.path.exists("/proc/stat"):
            snap = self._fake_snapshot()
            self._prev_cpu, self._prev_net = None, None
            return snap
        total, idle, cores = self._read_cpu()
        rx, tx = self._read_net()
        tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        now = time.time()
        snap = {"t": now, "ts": now_iso(), "mem": self._read_mem(), "disk": self._read_disk(),
                "procs": self._read_proc_count(), "uptime": self._read_uptime(),
                "rx_total": rx, "tx_total": tx}
        try:
            load = read_text("/proc/loadavg").split()
            snap["load"] = [float(load[0]), float(load[1]), float(load[2])]
        except (IndexError, ValueError):
            snap["load"] = [0.0, 0.0, 0.0]
        if self._prev_cpu and self._prev_net:
            p_total, p_idle, p_cores = self._prev_cpu
            d_total, d_idle = total - p_total, idle - p_idle
            snap["cpu"] = round(100.0 * (d_total - d_idle) / d_total, 1) if d_total else 0.0
            snap["cores"] = []
            for i, (c_total, c_idle) in enumerate(cores):
                if i < len(p_cores):
                    dt, di = c_total - p_cores[i][0], c_idle - p_cores[i][1]
                    snap["cores"].append(round(100.0 * (dt - di) / dt, 1) if dt else 0.0)
            dt = max(1e-6, now - self._prev_net[0])
            snap["rx_bps"] = max(0.0, (rx - self._prev_net[1]) / dt)
            snap["tx_bps"] = max(0.0, (tx - self._prev_net[2]) / dt)
        else:
            snap["cpu"], snap["cores"], snap["rx_bps"], snap["tx_bps"] = 0.0, [], 0.0, 0.0
        snap["cpu_count"] = len(cores) or (os.cpu_count() or 1)
        self._prev_cpu = (total, idle, cores)
        self._prev_net = (now, rx, tx)
        return snap

    def _loop(self):
        # 第一次采样只能拿到基准值（没有差值），所以先采一次再进循环
        has_proc = os.path.exists("/proc/stat") and not self.fake
        if has_proc:
            try:
                self._prev_cpu = self._read_cpu()
                rx, tx = self._read_net()
                self._prev_net = (time.time(), rx, tx)
            except Exception:  # noqa: BLE001
                pass
        while not self._stopped:
            try:
                # 先采一次再睡：否则开局几秒里 latest() 是空的，界面一片 0
                snap = self._snapshot()
                with self.lock:
                    self.samples.append(snap)
            except Exception:  # noqa: BLE001
                pass
            time.sleep(self.interval)

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        for _ in range(40):
            if self.latest():
                break
            time.sleep(0.05)

    def latest(self):
        with self.lock:
            return dict(self.samples[-1]) if self.samples else {}

    def series(self):
        with self.lock:
            return [{"t": s["t"], "cpu": s.get("cpu", 0), "rx": s.get("rx_bps", 0),
                     "tx": s.get("tx_bps", 0)} for s in self.samples]


# --------------------------------------------------------------------------
# systemd：服务列表、详情、日志
# --------------------------------------------------------------------------
class Services:
    """托管机上的 systemd 单元。没有 systemctl 就整体降级，不假装在管。"""

    def __init__(self):
        self.available = bool(shutil.which("systemctl"))
        self.hint = "" if self.available else "这台机器上没有 systemctl（多半是在容器里）"

    def list(self):
        if not self.available:
            return {"available": False, "hint": self.hint, "units": []}
        code, out, err = run(["systemctl", "list-units", "--type=service", "--all",
                              "--no-pager", "--no-legend", "--plain"], timeout=15)
        units = []
        for line in out.splitlines():
            f = line.split(None, 4)
            if len(f) < 4:
                continue
            units.append({"unit": f[0].lstrip("●").strip(), "load": f[1], "active": f[2],
                          "sub": f[3], "desc": (f[4] if len(f) > 4 else "").strip()})
        units.sort(key=lambda u: (u["active"] != "active", u["unit"]))
        return {"available": True, "units": units, "error": err.strip()[:200],
                "running": sum(1 for u in units if u["active"] == "active"),
                "failed": sum(1 for u in units if u["active"] == "failed")}

    def detail(self, unit):
        """一个单元的关键状态。show 是机器可读的，比 status 好解析。"""
        if not self.available or not UNIT_RE.match(unit or ""):
            return {"ok": False, "error": "单元名不合法或 systemd 不可用"}
        props = ("ActiveState", "SubState", "MainPID", "ExecMainStartTimestamp",
                 "Description", "UnitFileState", "MemoryCurrent", "CPUUsageNSec",
                 "NRestarts", "FragmentPath")
        code, out, err = run(["systemctl", "show", unit, "-p", ",".join(props)], timeout=10)
        if code != 0:
            return {"ok": False, "error": (err or out).strip()[:200]}
        info = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip()
        mem, cpu_ns = info.get("MemoryCurrent", ""), info.get("CPUUsageNSec", "")
        return {
            "ok": True, "unit": unit, "desc": info.get("Description", ""),
            "active": info.get("ActiveState", ""), "sub": info.get("SubState", ""),
            "pid": info.get("MainPID", "") if info.get("MainPID") not in ("", "0") else "",
            "since": info.get("ExecMainStartTimestamp", ""),
            "enabled": info.get("UnitFileState", ""),
            "restarts": info.get("NRestarts", ""),
            "fragment": info.get("FragmentPath", ""),
            "memory": int(mem) if mem.isdigit() else None,
            "cpu_sec": round(int(cpu_ns) / 1e9, 2) if cpu_ns.isdigit() else None,
        }

    def logs(self, unit, lines=200):
        if not self.available or not UNIT_RE.match(unit or ""):
            return {"available": False, "lines": ["单元名不合法或 systemd 不可用"]}
        code, out, err = run(["journalctl", "-u", unit, "-n", str(lines), "--no-pager",
                              "-o", "short-iso"], timeout=20)
        return {"available": code == 0, "lines": out.splitlines(),
                "error": err.strip()[:200] if code != 0 else ""}


# --------------------------------------------------------------------------
# Docker：容器列表、日志、启停
# --------------------------------------------------------------------------
class Docker:
    """Docker 容器。docker 不在就没有这一块，不影响其它功能。"""

    def __init__(self, stats_ttl=5.0):
        self.available = bool(shutil.which("docker"))
        self.hint = "" if self.available else "这台机器上没有 docker 命令"
        self._cache = (0.0, None)
        self._stats = (0.0, {})
        self.stats_ttl = stats_ttl

    def _json_lines(self, argv, timeout=25):
        code, out, err = run(argv, timeout=timeout)
        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
        return code, items, err

    def stats(self):
        """docker stats 有 1~2 秒开销，缓存起来，别每次刷新都付。"""
        now = time.time()
        if now - self._stats[0] < self.stats_ttl:
            return self._stats[1]
        code, items, _ = self._json_lines(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=25)
        out = {}
        for c in items:
            out[c.get("Name", "")] = {
                "cpu": c.get("CPUPerc", ""), "mem": c.get("MemUsage", ""),
                "mem_pct": c.get("MemPerc", ""), "net": c.get("NetIO", ""),
                "block": c.get("BlockIO", ""), "pids": c.get("PIDs", ""),
            }
        self._stats = (now, out)
        return out

    def list(self, with_stats=True):
        if not self.available:
            return {"available": False, "hint": self.hint, "containers": []}
        code, items, err = self._json_lines(
            ["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], timeout=25)
        stats = self.stats() if (with_stats and code == 0) else {}
        out = []
        for c in items:
            name = c.get("Names", "")
            out.append({"id": c.get("ID", "")[:12], "name": name, "image": c.get("Image", ""),
                        "state": c.get("State", ""), "status": c.get("Status", ""),
                        "ports": c.get("Ports", ""), "running": c.get("State") == "running",
                        "stats": stats.get(name, {})})
        out.sort(key=lambda x: (not x["running"], x["name"]))
        return {"available": True, "containers": out, "error": err.strip()[:200] if code != 0 else "",
                "running": sum(1 for x in out if x["running"])}

    def logs(self, name, lines=200):
        if not self.available or not NAME_RE.match(name or ""):
            return {"available": False, "lines": ["容器名不合法"]}
        code, out, err = run(["docker", "logs", "--tail", str(lines), name], timeout=25)
        text = (out or "") + (err or "")
        return {"available": code == 0, "lines": text.splitlines()[-lines:],
                "error": "" if code == 0 else text.strip()[:200]}

    def images(self):
        if not self.available:
            return {"available": False, "images": []}
        code, items, err = self._json_lines(
            ["docker", "images", "--format", "{{json .}}"], timeout=25)
        return {"available": code == 0, "error": err.strip()[:200] if code != 0 else "",
                "images": [{"repo": i.get("Repository", ""), "tag": i.get("Tag", ""),
                            "id": i.get("ID", ""), "size": i.get("Size", ""),
                            "created": i.get("CreatedSince", "")} for i in items]}


# --------------------------------------------------------------------------
# 安全面：登录失败、防火墙、fail2ban、SSH 配置
# --------------------------------------------------------------------------
class Security:
    """只读观测为主。处置动作（封 IP、解封）走白名单动作表。"""

    RE_FAIL = re.compile(
        r"(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*?"
        r"(?:Failed password for (?:invalid user )?(?P<u1>\S+)|Invalid user (?P<u2>\S+)|"
        r"Failed publickey for (?:invalid user )?(?P<u3>\S+)).*?"
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+)")
    RE_OK = re.compile(
        r"(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*?"
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

    def logins(self, lines=6000, top=10):
        text = []
        for f in ("/var/log/auth.log.1", "/var/log/auth.log"):
            if os.path.exists(f):
                text += read_text(f).splitlines()[-lines:]
        fails, oks = [], []
        for line in text:
            if "sshd" not in line:
                continue
            m = self.RE_FAIL.search(line)
            if m:
                fails.append({"ts": m.group("ts"), "ip": m.group("ip"),
                              "user": m.group("u1") or m.group("u2") or m.group("u3") or "?"})
                continue
            m = self.RE_OK.search(line)
            if m:
                oks.append({"ts": m.group("ts"), "ip": m.group("ip"), "user": m.group("user")})
        ips = collections.Counter(f["ip"] for f in fails)
        users = collections.Counter(f["user"] for f in fails)
        return {"available": bool(text), "failed": len(fails), "accepted": len(oks),
                "top_ips": [{"ip": k, "n": v} for k, v in ips.most_common(top)],
                "top_users": [{"user": k, "n": v} for k, v in users.most_common(top)],
                "recent": fails[-top:][::-1], "recent_ok": oks[-6:][::-1]}

    def firewall(self):
        if not shutil.which("ufw"):
            return {"available": False, "hint": "这台机器上没装 ufw"}
        code, out, err = run(["ufw", "status", "verbose"], timeout=15)
        rules = [l.rstrip() for l in out.splitlines()
                 if l.strip() and not l.startswith(("Status:", "Logging:", "Default:",
                                                    "New profiles:", "To ", "--"))]
        return {"available": True, "active": "Status: active" in out,
                "rules": rules[:40], "raw": out.strip()[:2500],
                "error": err.strip()[:200] if code != 0 else ""}

    def fail2ban(self):
        if not shutil.which("fail2ban-client"):
            return {"available": False, "hint": "这台机器上没装 fail2ban"}
        code, out, err = run(["fail2ban-client", "status"], timeout=15)
        jails = []
        m = re.search(r"Jail list:\s*(.+)", out)
        if m:
            jails = [j.strip() for j in m.group(1).split(",") if j.strip()]
        detail = {}
        for j in jails[:6]:
            c, o, _ = run(["fail2ban-client", "status", j], timeout=15)
            if c == 0:
                detail[j] = o.strip()[:1200]
        return {"available": code == 0, "jails": jails, "detail": detail,
                "error": err.strip()[:200] if code != 0 else ""}

    def sshd(self):
        keys = {}
        for line in read_text("/etc/ssh/sshd_config").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or " " not in s:
                continue
            k, v = s.split(None, 1)
            keys[k] = v.strip()
        want = ("Port", "PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
                "PermitEmptyPasswords", "MaxAuthTries", "ChallengeResponseAuthentication",
                "AllowUsers", "KbdInteractiveAuthentication")
        cfg = {k: keys.get(k, "(默认)") for k in want}
        auth = Path("/root/.ssh/authorized_keys")
        n = 0
        if auth.exists():
            n = len([l for l in read_text(str(auth)).splitlines()
                     if l.strip() and not l.lstrip().startswith("#")])
        return {"config": cfg, "authorized_keys": n,
                "note": "authorized_keys 为空时不要关密码登录，否则会把自己锁在外面" if not n else ""}


# --------------------------------------------------------------------------
# 端口 / 连接 / 进程
# --------------------------------------------------------------------------
class Ports:
    RE_SS = re.compile(
        r"^(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+\S+\s+\S+\s+(?P<local>\S+)\s+(?P<peer>\S+)"
        r"(?:\s+users:\(\((?P<proc>\"[^\"]+\",pid=\d+|[^)]*)\))?")
    RE_PROC = re.compile(r"\"(?P<name>[^\"]+)\",pid=(?P<pid>\d+)")

    def listening(self):
        if not shutil.which("ss"):
            return {"available": False, "hint": "没有 ss 命令", "ports": []}
        code, out, err = run(["ss", "-lntup"], timeout=15)
        ports = []
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) < 5 or f[0] not in ("tcp", "udp"):
                continue
            m = self.RE_PROC.search(line)
            ports.append({
                "proto": f[0], "local": f[4],
                "addr": f[4].rsplit(":", 1)[0] or "*", "port": f[4].rsplit(":", 1)[-1],
                "process": m.group("name") if m else "",
                "pid": m.group("pid") if m else "",
                "exposed": not f[4].startswith(("127.", "[::1]", "::1")),
            })
        ports.sort(key=lambda p: (not p["exposed"], p["port"]))
        return {"available": True, "ports": ports,
                "exposed": sum(1 for p in ports if p["exposed"]),
                "error": err.strip()[:200] if code != 0 else ""}

    def established(self, limit=40):
        code, out, err = run(["ss", "-tun"], timeout=15)
        rows = []
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) < 6 or "ESTAB" not in f[1]:
                continue
            rows.append({"proto": f[0], "local": f[4], "peer": f[5]})
            if len(rows) >= limit:
                break
        return {"connections": rows, "error": err.strip()[:200] if code != 0 else ""}


class Processes:
    def top(self, by="cpu", n=15):
        flag = "-pmem" if by == "mem" else "-pcpu"
        code, out, err = run(["ps", "-eo", "pid,ppid,user:14,pcpu,pmem,rss,etimes,stat,comm,args",
                              "--sort=" + flag, "--no-headers"], timeout=15)
        rows = []
        for line in out.splitlines()[:max(0, n)]:
            f = line.split(None, 9)
            if len(f) < 10:
                continue
            try:
                rows.append({"pid": f[0], "ppid": f[1], "user": f[2], "cpu": float(f[3]),
                             "mem": float(f[4]), "rss": int(f[5]) * 1024, "etimes": int(f[6]),
                             "stat": f[7], "comm": f[8], "args": f[9][:180]})
            except ValueError:
                continue
        return {"top": rows, "error": err.strip()[:200] if code != 0 else ""}

    def counts(self):
        total = zombie = 0
        for name in os.listdir("/proc") if os.path.isdir("/proc") else []:
            if not name.isdigit():
                continue
            total += 1
            try:
                if read_text("/proc/%s/stat" % name).split(") ", 1)[1][0] == "Z":
                    zombie += 1
            except (IndexError, OSError):
                pass
        return {"total": total, "zombie": zombie}


# --------------------------------------------------------------------------
# 白名单动作：面板能改变系统状态的全部手段，就这一张表
# --------------------------------------------------------------------------
def _val_unit(v):
    v = (v or "").strip()
    if not UNIT_RE.match(v):
        raise ValueError("单元名不合法")
    return v


def _val_name(v):
    v = (v or "").strip()
    if not NAME_RE.match(v):
        raise ValueError("名字不合法")
    return v


def _val_ip(v):
    import ipaddress
    try:
        return str(ipaddress.ip_address((v or "").strip()))
    except ValueError:
        raise ValueError("IP 不合法")


def _val_pid(v):
    n = int(str(v or "").strip())
    if not (1 <= n <= 4194304):
        raise ValueError("PID 不合法")
    return str(n)


ACTIONS = {
    "service.start": {"label": "启动服务", "desc": "systemctl start <单元>",
                      "params": {"unit": _val_unit}, "danger": False,
                      "argv": lambda p: ["systemctl", "start", p["unit"]]},
    "service.restart": {"label": "重启服务", "desc": "systemctl restart <单元>",
                        "params": {"unit": _val_unit}, "danger": False,
                        "argv": lambda p: ["systemctl", "restart", p["unit"]]},
    "service.stop": {"label": "停止服务", "desc": "systemctl stop <单元>",
                     "params": {"unit": _val_unit}, "danger": True,
                     "argv": lambda p: ["systemctl", "stop", p["unit"]]},
    "systemd.reload": {"label": "重载 systemd 单元配置", "desc": "systemctl daemon-reload",
                       "params": {}, "danger": False,
                       "argv": lambda p: ["systemctl", "daemon-reload"]},
    "docker.start": {"label": "启动容器", "desc": "docker start <容器>",
                     "params": {"name": _val_name}, "danger": False,
                     "argv": lambda p: ["docker", "start", p["name"]]},
    "docker.restart": {"label": "重启容器", "desc": "docker restart <容器>",
                       "params": {"name": _val_name}, "danger": False,
                       "argv": lambda p: ["docker", "restart", p["name"]], "timeout": 60},
    "docker.stop": {"label": "停止容器", "desc": "docker stop <容器>",
                    "params": {"name": _val_name}, "danger": True,
                    "argv": lambda p: ["docker", "stop", p["name"]], "timeout": 60},
    "docker.prune_images": {"label": "清理无标签镜像", "desc": "docker image prune -f",
                            "params": {}, "danger": True,
                            "argv": lambda p: ["docker", "image", "prune", "-f"], "timeout": 120},
    "process.term": {"label": "结束进程（TERM）", "desc": "kill -TERM <pid>",
                     "params": {"pid": _val_pid}, "danger": True,
                     "argv": lambda p: ["kill", "-TERM", p["pid"]]},
    "process.kill": {"label": "强杀进程（KILL）", "desc": "kill -KILL <pid>",
                     "params": {"pid": _val_pid}, "danger": True,
                     "argv": lambda p: ["kill", "-KILL", p["pid"]]},
    "ufw.deny": {"label": "防火墙封禁来源 IP", "desc": "ufw deny from <ip>",
                 "params": {"ip": _val_ip}, "danger": True,
                 "argv": lambda p: ["ufw", "deny", "from", p["ip"]], "timeout": 30},
    "ufw.undeny": {"label": "解封来源 IP", "desc": "ufw delete deny from <ip>",
                   "params": {"ip": _val_ip}, "danger": False,
                   "argv": lambda p: ["ufw", "--force", "delete", "deny", "from", p["ip"]],
                   "timeout": 30},
    "fail2ban.unban": {"label": "fail2ban 解封 IP", "desc": "fail2ban-client set <jail> unbanip <ip>",
                       "params": {"jail": _val_name, "ip": _val_ip}, "danger": False,
                       "argv": lambda p: ["fail2ban-client", "set", p["jail"], "unbanip", p["ip"]]},
    "journal.vacuum": {"label": "清理 journal 到最近 7 天", "desc": "journalctl --vacuum-time=7d",
                       "params": {}, "danger": True,
                       "argv": lambda p: ["journalctl", "--vacuum-time=7d"], "timeout": 120},
    "apt.update": {"label": "刷新软件包索引", "desc": "apt-get update",
                   "params": {}, "danger": False,
                   "argv": lambda p: ["apt-get", "update"], "timeout": 300},
}


class Audit:
    """审计日志：所有改变系统状态的尝试都追加一行 JSON。落盘的只有这个。"""

    def __init__(self, path, max_bytes=2 << 20):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.lock = threading.Lock()

    def write(self, action, target, ok, detail, ip):
        entry = {"ts": now_iso(), "t": int(time.time()), "ip": ip, "action": action,
                 "target": target, "ok": bool(ok), "detail": (detail or "")[:600]}
        with self.lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    shutil.copy2(str(self.path), str(self.path) + ".1")
                    open(self.path, "w", encoding="utf-8").close()
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError:
                pass
        return entry

    def tail(self, n=200):
        out = []
        for line in read_text(str(self.path)).splitlines()[-n:][::-1]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out


class Enforcer:
    """从 Nimbus 面板拉「该封谁 / 该解封谁」，用本机的白名单动作执行，再把结果回报。

    为什么是它拉、而不是 Nimbus 推：防火墙的权柄本来就该留在宿主机上；而且 Nimbus
    的面板已经发布在宿主的 127.0.0.1:8099，宿主直接就能连 —— 不用开新端口，也不用
    给容器任何特权。执行仍然走 ACTIONS 那张表（ufw.deny / ufw.undeny），所以自动封禁
    和手动封禁一样有审计。
    """

    def __init__(self, url, token, interval, audit, timeout=15):
        self.url = (url or "").rstrip("/")
        self.token = token or ""
        self.interval = max(10, int(interval or 60))
        self.audit = audit
        self.timeout = timeout
        self.enabled = bool(self.url and self.token)
        self.last = {"ts": 0, "ok": None, "banned": [], "unbanned": [], "error": ""}
        self.lock = threading.Lock()

    # --- 与 Nimbus 的两次对话 ---------------------------------------------
    def _call(self, path, method="GET", body=None):
        if not self.enabled:
            return False, {"error": "没配 --enforce-url / --enforce-token"}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            "User-Agent": "steward-enforcer"})
        try:
            # 这是本机回环调用，必须绕开环境里的 HTTP(S)_PROXY
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8", "replace")
            return True, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            return False, {"error": "HTTP %d：%s" % (e.code, e.read().decode("utf-8", "replace")[:200])}
        except Exception as e:  # noqa: BLE001
            return False, {"error": "%s: %s" % (type(e).__name__, e)}

    def poll_once(self):
        """跑一轮：拉取 → 执行 → 回报。返回这一轮的结果（也给界面看）。"""
        result = {"ts": int(time.time()), "ok": True, "banned": [], "unbanned": [], "error": ""}
        ok, data = self._call("/api/enforce/pending")
        if not ok:
            result.update(ok=False, error=data.get("error", "拉不到待执行列表"))
            self._remember(result)
            return result
        for item in (data.get("ban") or []):
            ip, reason, detail = item.get("ip"), item.get("reason", ""), item.get("detail", "")
            run = run_action("ufw.deny", {"ip": ip}, "nimbus", self.audit)
            self._call("/api/enforce/report", "POST", {
                "ip": ip, "action": "ban", "ok": run.get("ok"), "reason": reason,
                "detail": detail, "response": (run.get("detail") or run.get("error") or "")[:300]})
            if run.get("ok"):
                result["banned"].append(ip)
            else:
                result.update(ok=False, error="封 %s 失败：%s" % (ip, run.get("error") or run.get("err")))
        for item in (data.get("unban") or []):
            ip, reason, detail = item.get("ip"), item.get("reason", ""), item.get("detail", "")
            run = run_action("ufw.undeny", {"ip": ip}, "nimbus", self.audit)
            self._call("/api/enforce/report", "POST", {
                "ip": ip, "action": "unban", "ok": run.get("ok"), "reason": reason,
                "detail": detail, "response": (run.get("detail") or run.get("error") or "")[:300]})
            if run.get("ok"):
                result["unbanned"].append(ip)
            else:
                result.update(ok=False, error="解封 %s 失败：%s" % (ip, run.get("error") or run.get("err")))
        self._remember(result)
        return result

    def _remember(self, result):
        with self.lock:
            self.last = result

    def status(self):
        with self.lock:
            last = dict(self.last)
        return {"enabled": self.enabled, "url": self.url, "interval": self.interval,
                "last": last,
                "note": "" if self.enabled else "没配 --enforce-url / --enforce-token，自动封禁关闭"}

    def loop(self):
        while True:
            try:
                self.poll_once()
            except Exception as e:  # noqa: BLE001
                self._remember({"ts": int(time.time()), "ok": False, "banned": [], "unbanned": [],
                                "error": "%s: %s" % (type(e).__name__, e)})
            time.sleep(self.interval)


def list_actions():    return [{"name": k, "label": v["label"], "desc": v["desc"], "danger": v["danger"],
             "params": sorted((v.get("params") or {}).keys())}
            for k, v in sorted(ACTIONS.items())]


def run_action(name, params, ip, audit, dry=False):
    """执行一个白名单动作。参数逐个过校验器，argv 直接交给 subprocess（不经 shell）。

    dry=True 时只走到"命令已拼好"这一步就返回（演示模式）：这样校验、审计、返回
    结构都和真机一致，只有最后一步不真的执行 —— 两条路的代码不分叉。
    """
    spec = ACTIONS.get(name)
    if not spec:
        return {"ok": False, "error": "没有这个动作：%s" % (name or "(空)")}
    clean = {}
    for key, validator in (spec.get("params") or {}).items():
        try:
            clean[key] = validator((params or {}).get(key))
        except (ValueError, TypeError, AttributeError) as e:
            return {"ok": False, "error": "参数 %s 不合法：%s" % (key, e)}
    argv = spec["argv"](clean)
    if not argv or not all(isinstance(a, str) and a and "\x00" not in a for a in argv):
        return {"ok": False, "error": "拼出来的命令不合法，已拦下"}
    if dry:
        entry = audit.write(name, " ".join(argv[1:]) or "-", True, "演示模式：未真的执行", ip)
        return {"ok": True, "demo": True, "argv": argv, "code": 0,
                "out": "演示模式：这条命令没有真的执行。", "err": "", "detail": "demo",
                "audit": entry, "danger": spec.get("danger", False)}
    code, out, err = run(argv, timeout=spec.get("timeout", 30))
    detail = (out.strip() or err.strip())[:600]
    ok = code == 0
    entry = audit.write(name, " ".join(argv[1:]) or "-", ok, detail, ip)
    return {"ok": ok, "code": code, "argv": argv, "out": out.strip()[:5000],
            "err": err.strip()[:2500], "detail": detail, "audit": entry,
            "danger": spec.get("danger", False)}


# --------------------------------------------------------------------------
# 数据聚合：把采集器拼成界面要的几块
# --------------------------------------------------------------------------
def host_info():
    rel = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            rel[k] = v.strip().strip('"')
    uname = os.uname() if hasattr(os, "uname") else None
    return {"hostname": socket.gethostname(), "os": rel.get("PRETTY_NAME", ""),
            "kernel": ("%s %s" % (uname.sysname, uname.release)) if uname else "",
            "arch": uname.machine if uname else "", "python": sys.version.split()[0]}


def _tail_file(path, lines=200):
    """只允许 /var/log 与面板数据目录下的普通文件；解析真实路径挡符号链接逃逸。"""
    if not path:
        return {"ok": False, "error": "没给路径"}
    real = os.path.realpath(path)
    if not any(real.startswith(d) for d in LOG_DIRS):
        return {"ok": False, "error": "只允许读 %s 下的文件" % "、".join(LOG_DIRS)}
    if not os.path.isfile(real):
        return {"ok": False, "error": "不是普通文件：%s" % real}
    try:
        size = os.path.getsize(real)
        # 大文件只读尾巴，别把 1 GB 的日志拖进内存
        with open(real, "r", encoding="utf-8", errors="replace") as fh:
            if size > 4 << 20:
                fh.seek(max(0, size - (1 << 20)))
                fh.readline()
            data = fh.readlines()[-lines:]
    except OSError as e:
        return {"ok": False, "error": "读不了：%s" % e}
    return {"ok": True, "path": real, "size": size,
            "lines": [l.rstrip("\n") for l in data]}


class HostProbe:
    """真机数据源。"""

    real = True

    def __init__(self, sampler, audit):
        self.sampler = sampler
        self.audit = audit
        self.services = Services()
        self.docker = Docker()
        self.security = Security()
        self.ports = Ports()
        self.processes = Processes()
        self.info = host_info()

    def overview(self):
        snap = self.sampler.latest()
        procs = self.processes.counts()
        svc = self.services.list() if self.services.available else {"units": [], "available": False}
        dk = self.docker.list(with_stats=False) if self.docker.available else {"containers": [], "available": False}
        logins = self.security.logins(lines=2000, top=3) if os.path.exists("/var/log/auth.log") else {}
        return {
            "info": self.info, "ts": snap.get("ts", ""), "uptime": snap.get("uptime", 0),
            "uptime_text": dur_text(snap.get("uptime", 0)),
            "cpu": {"percent": snap.get("cpu", 0), "cores": snap.get("cores", []),
                    "count": snap.get("cpu_count", 1), "load": snap.get("load", [0, 0, 0])},
            "mem": snap.get("mem", {}), "disk": snap.get("disk", []),
            "net": {"rx_bps": snap.get("rx_bps", 0), "tx_bps": snap.get("tx_bps", 0),
                    "rx_total": snap.get("rx_total", 0), "tx_total": snap.get("tx_total", 0)},
            "procs": procs, "series": self.sampler.series(),
            "services": {"available": svc.get("available", False),
                         "total": len(svc.get("units", [])),
                         "running": svc.get("running", 0), "failed": svc.get("failed", 0)},
            "docker": {"available": dk.get("available", False),
                       "total": len(dk.get("containers", [])),
                       "running": dk.get("running", 0)},
            "security": {"failed": logins.get("failed", 0),
                         "top": (logins.get("top_ips") or [{}])[0].get("ip", ""),
                         "failed_24h_note": "来自 auth.log 全量统计"},
        }


class _DemoServices:
    """演示用的假 systemd。数据结构与真机一致，界面代码完全不用分叉。"""

    available = True
    hint = ""
    UNITS = [
        ("ssh.service", "active", "running", "OpenBSD Secure Shell server"),
        ("cron.service", "active", "running", "Regular background program processing daemon"),
        ("docker.service", "active", "running", "Docker Application Container Engine"),
        ("containerd.service", "active", "running", "containerd container runtime"),
        ("fail2ban.service", "failed", "failed", "Fail2Ban Service"),
        ("nginx.service", "inactive", "dead", "A high performance web server"),
    ]

    def list(self):
        units = [{"unit": u, "load": "loaded", "active": a, "sub": s, "desc": d}
                 for u, a, s, d in self.UNITS]
        return {"available": True, "units": units, "error": "",
                "running": sum(1 for u in units if u["active"] == "active"),
                "failed": sum(1 for u in units if u["active"] == "failed")}

    def detail(self, unit):
        u = next((x for x in self.UNITS if x[0] == unit), self.UNITS[0])
        return {"ok": True, "unit": u[0], "desc": u[3], "active": u[1], "sub": u[2],
                "pid": "1371" if unit == "ssh.service" else "602", "since": "2026-10-09 03:12:41 CST",
                "enabled": "enabled", "restarts": "0", "fragment": "/lib/systemd/system/" + u[0],
                "memory": 6 << 20, "cpu_sec": 1.42}

    def logs(self, unit, lines=200):
        return {"available": True, "lines": [
            "2026-10-09T03:12:41+0800 %s Starting %s..." % (unit, unit),
            "2026-10-09T03:12:41+0800 %s Started %s." % (unit, unit),
            "2026-10-09T03:15:02+0800 %s 演示模式：这里会是真实日志" % unit,
        ], "error": ""}


class _DemoDocker:
    available = True
    hint = ""

    def list(self, with_stats=True):
        cs = [("kms", "nimbus:local", "Up 3 minutes (healthy)", True),
              ("caddy", "caddy:2-alpine", "Up 26 minutes", True),
              ("old-test", "alpine:3.19", "Exited (0) 2 days ago", False)]
        out = []
        for name, image, status, running in cs:
            out.append({"id": (name + "0123456789ab")[:12], "name": name, "image": image,
                        "state": "running" if running else "exited", "status": status,
                        "ports": "1688:1688" if name == "kms" else ("80:80, 443:443" if name == "caddy" else ""),
                        "running": running,
                        "stats": {"cpu": "0.42%", "mem": "48MiB / 1.94GiB", "mem_pct": "2.4%",
                                  "net": "1.2MB / 860kB", "pids": "3"} if running else {}})
        return {"available": True, "containers": out, "error": "",
                "running": sum(1 for c in out if c["running"])}

    def logs(self, name, lines=200):
        return {"available": True, "lines": [
            "[entrypoint] reusing token from /var/lib/nimbus/nimbus.token",
            "nimbus 0.2.0  [real 模式]",
            "vlmcsd 5978b33 started successfully",
            "(演示模式：%s 的真实日志会出现在这里)" % name,
        ], "error": ""}

    def images(self):
        return {"available": True, "error": "", "images": [
            {"repo": "nimbus", "tag": "local", "id": "487970c6a7a8", "size": "72.4MB", "created": "10 minutes ago"},
            {"repo": "caddy", "tag": "2-alpine", "id": "1f534b35d111", "size": "51.2MB", "created": "3 days ago"},
            {"repo": "<none>", "tag": "<none>", "id": "9a8b7c6d5e4f", "size": "7.8MB", "created": "2 weeks ago"},
        ]}


class _DemoSecurity:
    def logins(self, lines=6000, top=10):
        fails = [{"ts": "Oct  9 03:19:48", "ip": "109.160.32.137", "user": "s10emmanuel"},
                 {"ts": "Oct  9 03:19:50", "ip": "109.160.32.110", "user": "kernbm"},
                 {"ts": "Oct  9 03:20:11", "ip": "109.160.32.137", "user": "postgres"},
                 {"ts": "Oct  9 03:20:33", "ip": "45.148.10.76", "user": "admin"}]
        return {"available": True, "failed": 1284, "accepted": 6,
                "top_ips": [{"ip": "109.160.32.137", "n": 742}, {"ip": "109.160.32.110", "n": 388},
                            {"ip": "45.148.10.76", "n": 154}],
                "top_users": [{"user": "s10emmanuel", "n": 210}, {"user": "kernbm", "n": 190},
                              {"user": "admin", "n": 120}, {"user": "postgres", "n": 88}],
                "recent": fails, "recent_ok": [
                    {"ts": "Oct  9 03:02:10", "ip": "39.144.169.199", "user": "root"}]}

    def firewall(self):
        return {"available": True, "active": False, "rules": [], "raw":
                "Status: inactive\n\n（演示数据）真机上这里显示 ufw 的规则表。", "error": ""}

    def fail2ban(self):
        return {"available": False, "hint": "这台机器上没装 fail2ban（演示）", "jails": [], "detail": {}}

    def sshd(self):
        return {"config": {"Port": "22", "PermitRootLogin": "yes", "PasswordAuthentication": "yes",
                           "PubkeyAuthentication": "yes", "PermitEmptyPasswords": "no",
                           "MaxAuthTries": "6", "ChallengeResponseAuthentication": "(默认)",
                           "AllowUsers": "(默认)", "KbdInteractiveAuthentication": "(默认)"},
                "authorized_keys": 0,
                "note": "authorized_keys 为空时不要关密码登录，否则会把自己锁在外面"}


class _DemoPorts:
    PORTS = [("tcp", "0.0.0.0:22", "22", "sshd", "1371", True),
             ("tcp", "0.0.0.0:80", "80", "docker-proxy", "27973", True),
             ("tcp", "0.0.0.0:443", "443", "docker-proxy", "27979", True),
             ("tcp", "0.0.0.0:1688", "1688", "docker-proxy", "37348", True),
             ("tcp", "127.0.0.1:8099", "8099", "docker-proxy", "37355", False),
             ("tcp", "127.0.0.1:8402", "8402", "python3", "41022", False)]

    def listening(self):
        ports = [{"proto": p, "local": l, "addr": l.rsplit(":", 1)[0] or "*", "port": port,
                  "process": proc, "pid": pid, "exposed": exp}
                 for p, l, port, proc, pid, exp in self.PORTS]
        return {"available": True, "ports": ports, "error": "",
                "exposed": sum(1 for p in ports if p["exposed"])}

    def established(self, limit=40):
        return {"connections": [{"proto": "tcp", "local": "38.76.207.46:22", "peer": "39.144.169.199:51234"}],
                "error": ""}


class _DemoProcesses:
    def top(self, by="cpu", n=15):
        rows = [("41022", "root", 4.2, 1.8, 42 << 20, 320, "R", "python3", "/usr/bin/python3 /opt/steward/steward.py"),
                ("27979", "root", 0.8, 0.4, 18 << 20, 1560, "S", "docker-proxy", "/usr/bin/docker-proxy -proto tcp"),
                ("602", "systemd+", 0.3, 0.6, 24 << 20, 4200, "S", "systemd-resolve", "/lib/systemd/systemd-resolved")]
        return {"top": [{"pid": r[0], "ppid": "1", "user": r[1], "cpu": r[2], "mem": r[3], "rss": r[4],
                         "etimes": r[5], "stat": r[6], "comm": r[7], "args": r[8]} for r in rows],
                "error": ""}

    def counts(self):
        return {"total": 138, "zombie": 1}


class DemoProbe:
    """演示数据源：没在 Linux 上也能把界面看全。"""

    real = False

    def __init__(self, sampler, audit):
        self.sampler = sampler
        self.audit = audit
        self.services = _DemoServices()
        self.docker = _DemoDocker()
        self.security = _DemoSecurity()
        self.ports = _DemoPorts()
        self.processes = _DemoProcesses()
        self.info = {"hostname": "demo-host", "os": "Ubuntu 22.04.4 LTS (演示)",
                     "kernel": "Linux 5.15.0-generic", "arch": "x86_64",
                     "python": sys.version.split()[0]}

    def overview(self):
        snap = self.sampler.latest()
        return {
            "info": self.info, "ts": snap.get("ts", ""), "uptime": snap.get("uptime", 0),
            "uptime_text": dur_text(snap.get("uptime", 0)),
            "cpu": {"percent": snap.get("cpu", 0), "cores": snap.get("cores", []),
                    "count": snap.get("cpu_count", 1), "load": snap.get("load", [0, 0, 0])},
            "mem": snap.get("mem", {}), "disk": snap.get("disk", []),
            "net": {"rx_bps": snap.get("rx_bps", 0), "tx_bps": snap.get("tx_bps", 0),
                    "rx_total": snap.get("rx_total", 0), "tx_total": snap.get("tx_total", 0)},
            "procs": snap.get("procs", {}) if isinstance(snap.get("procs"), dict)
                     else {"total": snap.get("procs", 0), "zombie": 0},
            "series": self.sampler.series(),
            "services": {"available": True, "total": 6, "running": 5, "failed": 1},
            "docker": {"available": True, "total": 3, "running": 2},
            "security": {"failed": 1284, "top": "109.160.32.137", "failed_24h_note": "演示数据"},
        }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "steward/" + VERSION
    app = None

    def log_message(self, fmt, *args):   # 访问日志：只留错误，别把 journald 刷满
        if str(args[1] if len(args) > 1 else "").startswith(("4", "5")):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # --- 基础设施 ---------------------------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        """把东西发出去。

        注意：**字符串原样发，不要 JSON 编码**。以前这里对任何非 bytes 都 json.dumps，
        于是 ui.html 被当成 JSON 字符串发出去（开头多个引号、换行变成字面 \\n、引号变成
        \\"），浏览器把整页当纯文本渲染 —— 表现就是「页面没有 CSS」。Nimbus 那边一直是
        分类型处理的，所以只有 Steward 中招。
        """
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else ""

    def _authed(self, q):
        """两种凭证：① 登录后发的会话令牌（浏览器）② 服务 token（机器）。

        服务 token 必须留着：Steward 每 60 秒要拿它去 Nimbus 拉限流决策，
        那种调用没法让人登录。它存在 0600 的文件里，只给机器用。
        """
        if q.get("token", [None])[0] == self.app["token"]:
            return True
        cred = self._bearer()
        if not cred:
            return False
        if self.app["accounts"].session_user(cred):
            return True
        return same_secret(cred, self.app["token"])

    def _user(self):
        """当前登录的账户名；用服务 token 进来的是 "(服务 token)"。"""
        cred = self._bearer()
        if not cred:
            return ""
        u = self.app["accounts"].session_user(cred)
        if u:
            return u
        return "(服务 token)" if same_secret(cred, self.app["token"]) else ""

    def _client_ip(self):
        """审计里记的客户端 IP。

        面板通常挂在反向代理后面，直连方是那个容器（172.x）—— 那样审计里全是
        "172.18.0.3 干了所有事"，等于没有。所以当直连方在信任网段内时，取
        X-Forwarded-For 的第一段（最左 = 最原始客户端）。直连方不在信任网段里就
        完全不看这个头，免得有人伪造。
        """
        peer = self.client_address[0]
        nets = self.app.get("allow_nets") or []
        if nets:
            import ipaddress
            try:
                addr = ipaddress.ip_address(peer)
            except ValueError:
                return peer
            if not any(addr in n for n in nets):
                return peer
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        return peer

    def _client_ok(self):
        """可选的来源白名单（--allow-ip）。绑回环/网桥时它只是第二层；绑 0.0.0.0 时它才是关键。"""
        nets = self.app.get("allow_nets") or []
        if not nets:
            return True
        import ipaddress
        try:
            addr = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if not n or n > 1 << 20:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # --- GET --------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._client_ok():
            return self._send(403, {"error": "forbidden", "hint": "来源不在 --allow-ip 白名单里"})
        if u.path in ("/", "/index.html"):
            return self._send(200, (HERE / "ui.html").read_text(encoding="utf-8"),
                              "text/html; charset=utf-8")
        if u.path == "/api/meta":
            return self._send(200, {"version": VERSION, "mode": self.app["mode"],
                                    "real": self.app["probe"].real, "started": self.app["started"],
                                    "interval": self.app["sampler"].interval,
                                    "actions": list_actions()})
        if u.path == "/api/auth":
            acc = self.app["accounts"]
            me = self._user()
            return self._send(200, {"need_setup": acc.need_setup(),
                                    "password_min": PASSWORD_MIN, "session_ttl": SESSION_TTL,
                                    "service_token": True, "me": me,
                                    # 没登录就不告诉你都有哪些用户名 —— 否则等于替攻击者
                                    # 把"猜用户名"这一步做了
                                    "users": acc.names() if me else []})
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized", "hint": "需要登录"})
        p = self.app["probe"]
        try:
            if u.path == "/api/overview":
                return self._send(200, p.overview())
            if u.path == "/api/services":
                return self._send(200, p.services.list())
            if u.path == "/api/service":
                return self._send(200, p.services.detail(q.get("unit", [""])[0]))
            if u.path == "/api/service/logs":
                return self._send(200, p.services.logs(q.get("unit", [""])[0],
                                                       int(q.get("lines", ["200"])[0])))
            if u.path == "/api/docker":
                return self._send(200, p.docker.list())
            if u.path == "/api/docker/images":
                return self._send(200, p.docker.images())
            if u.path == "/api/docker/logs":
                return self._send(200, p.docker.logs(q.get("name", [""])[0],
                                                     int(q.get("lines", ["200"])[0])))
            if u.path == "/api/security":
                return self._send(200, {"logins": p.security.logins(),
                                        "firewall": p.security.firewall(),
                                        "fail2ban": p.security.fail2ban(),
                                        "sshd": p.security.sshd()})
            if u.path == "/api/ports":
                return self._send(200, {"listening": p.ports.listening(),
                                        "established": p.ports.established()})
            if u.path == "/api/processes":
                return self._send(200, {"top": p.processes.top(q.get("by", ["cpu"])[0]),
                                        "counts": p.processes.counts()})
            if u.path == "/api/audit":
                return self._send(200, {"entries": p.audit.tail(int(q.get("lines", ["200"])[0]))})
            if u.path == "/api/enforce":
                return self._send(200, self.app["enforcer"].status())
            if u.path == "/api/accounts":
                return self._send(200, {"users": self.app["accounts"].listing(),
                                        "me": self._user(),
                                        "guard": self.app["guard"].status()})
            if u.path == "/api/log":
                return self._send(200, _tail_file(q.get("path", [""])[0],
                                                  int(q.get("lines", ["200"])[0])))
            if u.path == "/api/journal":
                code, out, err = run(["journalctl", "-n", str(int(q.get("lines", ["200"])[0])),
                                      "--no-pager", "-o", "short-iso"], timeout=20)
                return self._send(200, {"available": code == 0, "lines": out.splitlines(),
                                        "error": err.strip()[:200] if code != 0 else ""})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})
        return self._send(404, {"error": "not found"})

    # --- POST -------------------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._client_ok():
            return self._send(403, {"error": "forbidden", "hint": "来源不在 --allow-ip 白名单里"})
        acc = self.app["accounts"]
        ip = self._client_ip()

        # --- 不需要登录的两个入口 -----------------------------------------
        if u.path == "/api/setup":
            if not acc.need_setup():
                return self._send(403, {"ok": False, "error": "已经有账户了，请直接登录"})
            body = self._json_body()
            name = (body.get("name") or "").strip()
            ok, err = acc.create(name, body.get("password") or "")
            if not ok:
                return self._send(400, {"ok": False, "error": err})
            acc.touch_login(name)
            self.app["audit"].write("account.setup", name, True, "首次设置账户", ip)
            return self._send(200, {"ok": True, "session": acc.new_session(name), "name": name})
        if u.path == "/api/login":
            wait = self.app["guard"].wait_seconds(ip)
            if wait:
                return self._send(429, {"ok": False, "error": "登录失败次数太多，请 %d 秒后再试" % wait})
            body = self._json_body()
            name = (body.get("name") or "").strip()
            if acc.check(name, body.get("password") or ""):
                self.app["guard"].ok(ip)
                acc.touch_login(name)
                self.app["audit"].write("account.login", name, True, "", ip)
                return self._send(200, {"ok": True, "session": acc.new_session(name), "name": name})
            blocked, secs, level = self.app["guard"].fail(ip)
            self.app["audit"].write("account.login", name or "(空)", False,
                                    "密码错误" + ("，已封禁 %d 秒（第 %d 档）" % (secs, level)
                                                  if blocked else ""), ip)
            return self._send(403, {"ok": False, "error": "用户名或密码不对"})

        # --- 以下都要已登录 -----------------------------------------------
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized"})
        body = self._json_body()
        me = self._user()

        if u.path == "/api/logout":
            acc.drop_session(self._bearer())
            return self._send(200, {"ok": True})
        if u.path == "/api/accounts/create":
            name = (body.get("name") or "").strip()
            ok, err = acc.create(name, body.get("password") or "")
            self.app["audit"].write("account.create", name, ok, err or "", ip)
            return self._send(200 if ok else 400,
                              {"ok": ok, "error": err, "users": acc.listing()})
        if u.path == "/api/accounts/password":
            # 改谁的密码都行，但必须拿"你自己当前的密码"确认一次 —— 免得一个会话被
            # 偷走就能静默接管所有账户
            if me == "(服务 token)" or not acc.check(me, body.get("actor_password") or ""):
                self.app["audit"].write("account.password", body.get("name") or me, False,
                                        "当前密码校验失败", ip)
                return self._send(403, {"ok": False, "error": "请输入你自己当前的密码"})
            target = (body.get("name") or me).strip()
            ok, err = acc.set_password(target, body.get("password") or "")
            if ok:
                acc.drop_user_sessions(target)      # 改完密码让旧会话全部失效
            self.app["audit"].write("account.password", target, ok, err or "", ip)
            return self._send(200 if ok else 400, {"ok": ok, "error": err})
        if u.path == "/api/accounts/delete":
            target = (body.get("name") or "").strip()
            ok, err = acc.delete(target)
            self.app["audit"].write("account.delete", target, ok, err or "", ip)
            return self._send(200 if ok else 400,
                              {"ok": ok, "error": err, "users": acc.listing()})
        if u.path == "/api/accounts/logout-all":
            n = acc.drop_user_sessions(me) if me and me != "(服务 token)" else 0
            self.app["audit"].write("account.logout_all", me, True, "退出 %d 个会话" % n, ip)
            return self._send(200, {"ok": True, "dropped": n})
        if u.path == "/api/accounts/unblock":
            # 自己手滑输错密码把自己封了，或者误封了好人：给一条明确的解封路。
            # 档位不清零，所以解封不等于给攻击者重置计数。
            try:
                who = _val_ip(body.get("ip"))
            except ValueError as e:
                return self._send(400, {"ok": False, "error": str(e)})
            cleared = self.app["guard"].unblock(who)
            self.app["audit"].write("account.unblock", who, True,
                                    "解封登录限流" if cleared else "本来就没封", ip)
            return self._send(200, {"ok": True, "cleared": cleared,
                                    "guard": self.app["guard"].status()})
        if u.path == "/api/action":
            return self._send(200, run_action(body.get("name", ""), body.get("params") or {}, ip,
                                              self.app["probe"].audit,
                                              dry=not self.app["probe"].real))
        return self._send(404, {"error": "not found"})


def main():
    # 控制台编码可能是 GBK / ASCII（Windows、LANG=C 的 Linux 都是），一句中文横幅就能
    # 让整个面板起不来。先把输出通道统一成 UTF-8 且遇错不炸。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="Steward —— Linux 服务器管理面板")
    ap.add_argument("--mode", choices=["demo", "real"], default="real")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="监听地址，逗号分隔可绑多个；写 docker 表示再绑一份宿主在 docker 网桥上的地址")
    ap.add_argument("--allow-ip", default=os.environ.get("STEWARD_ALLOW_IP", ""),
                    help="来源白名单（逗号分隔的网段）；留空 = 不限制，靠绑定地址与 token 守门")
    ap.add_argument("--port", type=int, default=8402)
    ap.add_argument("--token", default="", help="直接给 token（默认从 token 文件读或生成）")
    ap.add_argument("--token-file", default="", help="默认 <data-dir>/steward.token")
    ap.add_argument("--data-dir", default="/var/lib/steward", help="token 与审计日志的目录")
    ap.add_argument("--interval", type=float, default=2.0, help="采样间隔（秒）")
    ap.add_argument("--enforce-url", default=os.environ.get("STEWARD_ENFORCE_URL", ""),
                    help="从哪个面板拉「该封谁」，例如 http://127.0.0.1:8099（Nimbus）")
    ap.add_argument("--enforce-token", default=os.environ.get("STEWARD_ENFORCE_TOKEN", ""),
                    help="上面那个面板的访问 token")
    ap.add_argument("--enforce-interval", type=int, default=60,
                    help="拉取间隔（秒），最小 10；0 表示关闭自动封禁")
    args = ap.parse_args()

    if args.mode == "demo":
        data_dir = Path(args.data_dir if args.data_dir != "/var/lib/steward"
                        else HERE / ".steward-demo-data")
    else:
        data_dir = Path(args.data_dir)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit("数据目录建不了：%s" % e)

    token = args.token or os.environ.get("STEWARD_TOKEN") or ""
    token_file = Path(args.token_file) if args.token_file else data_dir / "steward.token"
    if not token:
        if token_file.exists():
            token = token_file.read_text(encoding="utf-8").strip()
        if not token:
            token = secrets.token_urlsafe(24)
            try:
                token_file.parent.mkdir(parents=True, exist_ok=True)
                token_file.write_text(token, encoding="utf-8")
                os.chmod(token_file, 0o600)
            except OSError as e:
                sys.exit("token 文件写不了：%s" % e)

    sampler = Sampler(interval=args.interval, fake=(args.mode == "demo"))
    audit = Audit(data_dir / "audit.log")
    accounts = Accounts(data_dir / "accounts.json")
    enforcer = Enforcer(args.enforce_url, args.enforce_token, args.enforce_interval, audit)
    if args.mode == "demo" or not args.enforce_interval:
        enforcer.enabled = False
    probe = DemoProbe(sampler, audit) if args.mode == "demo" else HostProbe(sampler, audit)
    app = {"probe": probe, "sampler": sampler, "token": token, "mode": args.mode,
           "started": now_iso(), "enforcer": enforcer, "accounts": accounts, "audit": audit,
           "guard": LoginGuard(data_dir / "loginguard.json"),
           "allow_nets": parse_networks(args.allow_ip)}
    Handler.app = app

    # 先把端口占住，再起采样线程：反过来的话 systemd 已经报 active、端口却还没监听，
    # 健康检查会踩空（install.sh 的健康检查就踩过一次）。
    servers = []
    for addr in expand_binds(args.bind):
        try:
            srv = ThreadingHTTPServer((addr, args.port), Handler)
        except OSError as e:
            print("  !! 绑不上 %s:%d（%s）" % (addr, args.port, e))
            continue
        srv.daemon_threads = True
        servers.append((addr, srv))
    if not servers:
        sys.exit("一个地址都没绑上，退出")
    for _, srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    sampler.start()
    if enforcer.enabled:
        threading.Thread(target=enforcer.loop, daemon=True).start()
    print("=" * 72)
    print("  steward %s  [%s 模式]" % (VERSION, args.mode))
    for addr, _ in servers:
        print("  监听 %s:%d" % (addr, args.port))
    print("  打开这个地址（已带 token）：http://%s:%d/?token=%s"
          % (servers[0][0] if servers[0][0] != "0.0.0.0" else "127.0.0.1", args.port, token))
    print("  纯 token：%s（机器凭证，浏览器改用账户登录）" % token)
    print("  忘了 token 就跑：cat %s" % token_file)
    print("  数据目录：%s（审计日志 %s）" % (data_dir, data_dir / "audit.log"))
    if accounts.need_setup():
        print("  注意：还没有账户，打开页面先设置账户名与密码")
    else:
        print("  账户：%s（改密码在面板的「账户」页）" % "、".join(accounts.names()))
    if app["allow_nets"]:
        print("  来源白名单：%s" % "、".join(str(n) for n in app["allow_nets"]))
    if args.mode == "real":
        print("  systemd：%s   docker：%s" % (
            "可用" if probe.services.available else "不可用",
            "可用" if probe.docker.available else "不可用"))
        print("  自动封禁：%s" % ("%s（每 %d 秒拉一次）" % (enforcer.url, enforcer.interval)
                                 if enforcer.enabled else "关闭"))
    print("=" * 72)
    sys.stdout.flush()
    try:
        servers[0][1].serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
