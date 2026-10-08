#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构自检：语法、界面里用到的 id 与图标是否都存在、有没有 shell 里跑的坏习惯。

CI 每次提交都跑；本地也能直接 python3 tools/check.py。
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
try:                       # Windows 控制台默认 GBK，✔ 这种字符会炸；CI 上是 UTF-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:          # noqa: BLE001
    pass
fails = []


def ok(cond, msg):
    print(("  ✔ " if cond else "  ✘ ") + msg)
    if not cond:
        fails.append(msg)


print("== 语法 ==")
r = subprocess.run([sys.executable, "-m", "py_compile", str(ROOT / "steward.py")],
                   capture_output=True, text=True)
ok(r.returncode == 0, "steward.py 能编译" + ("" if r.returncode == 0 else "：" + r.stderr[-400:]))

html = (ROOT / "ui.html").read_text(encoding="utf-8")
m = re.search(r"<script>(.*)</script>", html, re.S)
ok(bool(m), "ui.html 里有 <script> 块")

print("== 界面自检 ==")
if m:
    js = m.group(1)
    ids = set(re.findall(r'id="([A-Za-z0-9_-]+)"', html))
    used = set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', js))
    ok(not (used - ids), "JS 用到的 id 都在 HTML 里：%s" % (sorted(used - ids) or "全部命中"))
    icons = set(re.findall(r'<use href="#(i-[a-z0-9-]+)"', html))
    sprite = set(re.findall(r'id="(i-[a-z0-9-]+)"', html))
    ok(not (icons - sprite), "用到的图标都定义了：%s" % (sorted(icons - sprite) or "全部命中"))
    if shutil.which("node"):
        tmp = pathlib.Path(tempfile.gettempdir()) / "steward-ui-check.js"
        tmp.write_text(js, encoding="utf-8")
        r = subprocess.run(["node", "--check", str(tmp)], capture_output=True, text=True)
        ok(r.returncode == 0, "界面 JS 语法通过" + ("" if r.returncode == 0 else "：" + r.stderr[:400]))
    else:
        print("  · 没装 node，跳过 JS 语法检查")

print("== 安全底线 ==")
src = (ROOT / "steward.py").read_text(encoding="utf-8")
ok("shell=True" not in src, "代码里没有 shell=True")
ok("os.system(" not in src, "代码里没有 os.system")
ok(bool(re.search(r"ACTIONS\s*=\s*\{", src)), "白名单动作表存在")
ok(bool(re.search(r"0o600|0o?600", src)), "token 文件按 600 权限写")

print()
if fails:
    print("失败 %d 项：" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("全部通过")
