#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演示模式冒烟测试：把面板拉起来，走一遍「首次设置账户 → 登录 → 账户管理」与所有接口。

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
TOKEN = "smoke-service-token"
USER = "smoke"
PASS = "smoke-password"
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

CRED = {"v": TOKEN}          # 先拿服务 token 顶着，登录后换成会话令牌


def call(path, method="GET", body=None, auth=True, cred=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), data=data, method=method)
    if auth:
        req.add_header("Authorization", "Bearer " + (cred if cred is not None else CRED["v"]))
    req.add_header("Content-Type", "application/json")
    try:
        with opener.open(req, timeout=25) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


try:
    for _ in range(80):
        try:
            call("/api/auth", auth=False)
            break
        except Exception:
            time.sleep(0.25)
    else:
        sys.exit("面板没起来")

    print("== 首次使用：还没有账户 ==")
    st, body = call("/api/auth", auth=False)
    d = json.loads(body)
    ok(st == 200 and d["need_setup"] is True, "GET /api/auth 说要先设置账户（need_setup=true）")
    ok(d["password_min"] >= 8, "最少密码长度是 %s" % d["password_min"])

    st, body = call("/api/overview", auth=False)
    ok(st == 401, "还没登录时 /api/overview 是 401")
    st, body = call("/api/setup", "POST", {"name": USER, "password": "短"}, auth=False)
    ok(st == 400 and "至少" in json.loads(body)["error"], "密码太短会被拒：%s"
       % json.loads(body).get("error"))

    st, body = call("/api/setup", "POST", {"name": USER, "password": PASS}, auth=False)
    d = json.loads(body)
    ok(st == 200 and d.get("session") and d.get("name") == USER, "首次设置成功并直接给了会话")
    CRED["v"] = d["session"]
    st, body = call("/api/setup", "POST", {"name": "x", "password": "xxxxxxxx"}, auth=False)
    ok(st == 403, "已经有账户后再调 /api/setup 会被拒")

    st, body = call("/api/auth", auth=False)
    ok(json.loads(body)["need_setup"] is False, "现在 need_setup 变成 false 了")

    print("== 接口（用会话令牌） ==")
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
    # 演示模式必须是确定性数据（空闲机器上真实 CPU 可能就是 0.0）
    ok(d["info"]["hostname"] == "demo-host", "演示模式用的是演示数据")
    ok(isinstance(d["cpu"]["percent"], (int, float)) and d["cpu"]["percent"] > 0,
       "概览有 CPU 数据：%s%%" % d["cpu"]["percent"])
    ok(d["mem"]["total"] > 0 and d["mem"]["percent"] > 0, "概览有内存数据：%.0f MB" % (d["mem"]["total"] >> 20))
    ok(bool(d["disk"]) and d["disk"][0]["total"] > 0, "概览有磁盘数据")
    ok(len(d["series"]) >= 1, "有曲线数据（%d 个采样点）" % len(d["series"]))

    print("== 账户管理 ==")
    st, body = call("/api/accounts")
    d = json.loads(body)
    ok([u["name"] for u in d["users"]] == [USER], "账户列表里只有 %s" % USER)
    ok(d["me"] == USER, "它知道当前登录的是谁：%s" % d["me"])

    st, body = call("/api/accounts/create", "POST", {"name": "second", "password": "second-pass"})
    ok(st == 200 and len(json.loads(body)["users"]) == 2, "能新增账户")
    st, body = call("/api/accounts/create", "POST", {"name": "second", "password": "second-pass"})
    ok(st == 400 and "已经有" in json.loads(body)["error"], "同名账户会被拒")
    st, body = call("/api/accounts/create", "POST", {"name": "带中文", "password": "whatever1"})
    ok(st == 400, "用户名格式不合法会被拒")

    # 用 second 登录（验证多账户都能登）
    st, body = call("/api/login", "POST", {"name": "second", "password": "second-pass"}, auth=False)
    ok(st == 200 and json.loads(body)["name"] == "second", "新账户能登录")
    second_session = json.loads(body).get("session", "")

    st, body = call("/api/accounts/password", "POST",
                    {"name": "second", "password": "second-pass2", "actor_password": PASS})
    ok(st == 200, "改别人的密码（用自己当前密码确认）成功")
    st, body = call("/api/accounts/password", "POST",
                    {"name": "second", "password": "second-pass3", "actor_password": "错的"})
    ok(st == 403, "当前密码不对时改不了密码")
    st, body = call("/api/overview", cred=second_session)
    ok(st == 401, "被改密码后，那个账户的旧会话失效了")
    st, body = call("/api/login", "POST", {"name": "second", "password": "second-pass2"}, auth=False)
    ok(st == 200, "用新密码能登录")

    st, body = call("/api/accounts/delete", "POST", {"name": "second"})
    ok(st == 200 and len(json.loads(body)["users"]) == 1, "能删除账户")
    st, body = call("/api/accounts/delete", "POST", {"name": USER})
    ok(st == 400 and "最后一个" in json.loads(body)["error"], "最后一个账户删不掉")

    print("== 凭证：服务 token 仍然给机器用 ==")
    st, body = call("/api/overview", cred=TOKEN)
    ok(st == 200, "服务 token 照样能调 API（Steward 自己就靠它拉限流决策）")
    st, body = call("/api/overview?token=" + TOKEN, cred="")
    ok(st == 200, "?token= 的老用法也还认（脚本兼容）")

    print("== 登录失败与限流 ==")
    st, body = call("/api/login", "POST", {"name": USER, "password": "错的"}, auth=False)
    ok(st == 403, "密码错 → 403：%s" % json.loads(body).get("error"))
    for _ in range(8):
        call("/api/login", "POST", {"name": USER, "password": "还是错的"}, auth=False)
    st, body = call("/api/login", "POST", {"name": USER, "password": PASS}, auth=False)
    ok(st == 429, "连续失败后会被临时拒绝（429），连正确密码也得等：%s"
       % json.loads(body).get("error"))

    print("== 安全底线 ==")
    st, _ = call("/api/overview", auth=False)
    ok(st == 401, "不带凭证一律 401")
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
    st, body = call("/api/audit")
    acts = [e["action"] for e in json.loads(body)["entries"]]
    ok("account.setup" in acts and "account.login" in acts, "账户事件也进审计：%s" % acts[:6])

    print("== 退出登录 ==")
    st, body = call("/api/logout", "POST")
    ok(st == 200, "POST /api/logout 成功")
    st, body = call("/api/overview", auth=False)
    ok(st == 401, "退出后没凭证 → 401")
    st, body = call("/api/login", "POST", {"name": USER, "password": PASS}, auth=False)
    ok(st == 403 or st == 429, "还在限流冷却里，登录仍被挡（%s）" % st)

    print("== 执法器流程（假 Nimbus） ==")
    sys.path.insert(0, str(ROOT))
    import http.server
    import threading
    import steward

    seen = []
    pending = {"ban": [{"ip": "203.0.113.9", "reason": "ip", "detail": "该 IP 今天激活 11 次"}],
               "unban": [], "limit": 10, "window": "day"}

    class FakeNimbus(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _out(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._out(pending if self.path.startswith("/api/enforce/pending") else {"error": "no"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen.append(json.loads(self.rfile.read(n) or b"{}"))
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
           "本机封不了（没 ufw 或不是 root）时如实回报失败，不假装成功")
        # 只断言「失败必须带原因」，别断言具体文案 —— 不同环境差别很大
        ok(res["ok"] is False and bool(res.get("error")),
           "失败原因如实带回来了：%s" % (res.get("error") or "")[:70])
        ok((workdir / "audit2.log").exists(), "执法经过写进了审计")
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
    if fails:
        print("\n---- 服务端日志（尾部） ----")
        print("\n".join(text.splitlines()[-20:]))

print()
if fails:
    print("失败 %d 项：" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("全部通过")
