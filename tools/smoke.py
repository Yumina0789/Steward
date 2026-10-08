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
    # 演示模式必须是确定性数据（哪怕是 Linux：空闲机器上真实 CPU 可能就是 0.0，
    # 早先这里断言 percent > 0 在 CI 上偶发失败 —— 那是测试的毛病，不是面板的）
    ok(d["info"]["hostname"] == "demo-host", "演示模式用的是演示数据")
    ok(isinstance(d["cpu"]["percent"], (int, float)) and d["cpu"]["percent"] > 0,
       "概览有 CPU 数据：%s%%" % d["cpu"]["percent"])
    ok(d["mem"]["total"] > 0 and d["mem"]["percent"] > 0, "概览有内存数据：%.0f MB" % (d["mem"]["total"] >> 20))
    ok(bool(d["disk"]) and d["disk"][0]["total"] > 0, "概览有磁盘数据")
    ok(len(d["series"]) >= 1, "有曲线数据（%d 个采样点）" % len(d["series"]))

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

    print("== 执法器流程（假 Nimbus） ==")
    sys.path.insert(0, str(ROOT))
    import http.server
    import json as _json
    import threading
    import steward

    seen = []
    pending = {"ban": [{"ip": "203.0.113.9", "reason": "ip", "detail": "该 IP 今天激活 11 次"}],
               "unban": [], "limit": 10, "window": "day"}

    class FakeNimbus(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _out(self, obj):
            data = _json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.startswith("/api/enforce/pending"):
                self._out(pending)
            else:
                self._out({"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen.append(_json.loads(self.rfile.read(n) or b"{}"))
            self._out({"ok": True})

    fake = http.server.ThreadingHTTPServer(("127.0.0.1", PORT + 1), FakeNimbus)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    try:
        enf = steward.Enforcer("http://127.0.0.1:%d" % (PORT + 1), "tok", 60,
                               steward.Audit(workdir / "audit2.log"))
        res = enf.poll_once()
        ok(any(s.get("action") == "ban" and s.get("ip") == "203.0.113.9" for s in seen),
           "把「封这个 IP」回报给了面板：%s" % seen)
        ok(seen and seen[0].get("ok") is False,
           "本机没有 ufw，如实回报失败而不是假装成功")
        ok(res["ok"] is False and "ufw" in _json.dumps(res, ensure_ascii=False),
           "失败原因带回来了：%s" % res.get("error", "")[:60])
        ok((workdir / "audit2.log").exists(), "执法经过写进了审计")
        # 解封路径
        pending["ban"] = []
        pending["unban"] = [{"ip": "203.0.113.9", "reason": "ttl", "detail": "已封满 24 小时"}]
        seen.clear()
        enf.poll_once()
        ok(any(s.get("action") == "unban" for s in seen), "解封请求也会被回报回去")
    finally:
        fake.shutdown()
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
