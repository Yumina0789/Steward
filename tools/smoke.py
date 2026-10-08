#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演示模式冒烟测试：把面板拉起来，逐个接口打一遍，顺便验证安全底线。

不碰任何真实系统状态（demo 数据源 + 临时数据目录），所以 CI 上随便跑。
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
try:                       # Windows 控制台默认 GBK，✔ 这种字符会炸；CI 上是 UTF-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:          # noqa: BLE001
    pass
PORT = 8439
TOKEN = "smoke-token"
fails = []


def ok(cond, msg):
    print(("  ✔ " if cond else "  ✘ ") + msg)
    if not cond:
        fails.append(msg)


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
workdir = pathlib.Path(tempfile.mkdtemp())
server_log = workdir / "server.log"
log_fh = open(str(server_log), "w", encoding="utf-8")
proc = subprocess.Popen([sys.executable, str(ROOT / "steward.py"), "--mode", "demo",
                         "--port", str(PORT), "--token", TOKEN, "--data-dir", str(workdir)],
                        stdout=log_fh, stderr=subprocess.STDOUT)


def call(path, method="GET", body=None, auth=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), data=data, method=method)
    if auth:
        req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Content-Type", "application/json")
    try:
        with opener.open(req, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


try:
    for _ in range(80):
        try:
            call("/api/meta", auth=False)
            break
        except Exception:
            time.sleep(0.25)
    else:
        sys.exit("面板没起来")

    print("== 接口 ==")
    for path, want in [("/", 200), ("/api/meta", 200), ("/api/overview", 200),
                       ("/api/services", 200), ("/api/service?unit=ssh.service", 200),
                       ("/api/service/logs?unit=ssh.service", 200), ("/api/docker", 200),
                       ("/api/docker/images", 200), ("/api/docker/logs?name=kms", 200),
                       ("/api/security", 200), ("/api/ports", 200), ("/api/processes", 200),
                       ("/api/audit", 200), ("/api/journal", 200), ("/api/nope", 404)]:
        try:
            st, _ = call(path)
        except Exception as e:  # noqa: BLE001
            st = "%s: %s" % (type(e).__name__, e)
        ok(st == want, "%-40s → %s" % (path, st))

    print("== 数据形状 ==")
    st, body = call("/api/overview")
    d = json.loads(body)
    ok(d["cpu"]["percent"] > 0 and d["mem"]["total"] > 0, "概览有 CPU 与内存数据")
    ok(isinstance(d["series"], list), "有曲线数据")

    print("== 安全底线 ==")
    st, _ = call("/api/overview", auth=False)
    ok(st == 401, "不带 token 一律 401")
    st, body = call("/api/action", "POST", {"name": "no.such.action"})
    ok(not json.loads(body)["ok"], "未知动作被拒绝")
    st, body = call("/api/action", "POST", {"name": "ufw.deny", "params": {"ip": "不是IP"}})
    ok(not json.loads(body)["ok"], "非法参数被拒绝")
    st, body = call("/api/log?path=/etc/passwd")
    ok(not json.loads(body)["ok"], "越界读文件被拒绝")
    st, body = call("/api/log?path=/var/log/../../etc/shadow")
    ok(not json.loads(body)["ok"], "用 .. 绕过目录限制被拒绝")
    st, body = call("/api/action", "POST", {"name": "ufw.deny", "params": {"ip": "1.2.3.4"}})
    ok(json.loads(body).get("demo") is True, "演示模式不真的执行命令")
    st, body = call("/api/audit")
    ok(len(json.loads(body)["entries"]) >= 1, "动作写进了审计")
    st, body = call("/api/login", "POST", {"token": "错的"})
    ok(st == 403, "错的 token 登不进来")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log_fh.close()
    text = server_log.read_text(encoding="utf-8", errors="replace")
    bad = [l for l in text.splitlines() if "Traceback" in l or "Error" in l or "error" in l]
    if bad or fails:
        print("\n---- 服务端日志（尾部） ----")
        print("\n".join(text.splitlines()[-25:]))

print()
if fails:
    print("失败 %d 项：" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("全部通过")
