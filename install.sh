#!/usr/bin/env bash
# Steward 安装脚本：把面板装成宿主机上的 systemd 服务。
#
#   curl -fsSL https://raw.githubusercontent.com/Yumina0789/Steward/main/install.sh | sudo bash
#   sudo bash install.sh --port 8402 --bind 127.0.0.1
#   sudo bash install.sh --uninstall          # 停掉并删服务，数据与 token 留着
#   sudo bash install.sh --purge              # 连数据一起删
#
# 为什么装在宿主机而不是容器：面板要管 systemd、进程、/proc、/var/log、docker，
# 容器化就得 privileged + 挂 docker.sock，隔离反而没了。见 docs/adr/0001。
set -euo pipefail

PREFIX="/opt/steward"
DATA_DIR="/var/lib/steward"
UNIT="/etc/systemd/system/steward.service"
PORT="8402"
BIND="127.0.0.1"
TOKEN=""
REPO_RAW="${STEWARD_REPO_RAW:-https://raw.githubusercontent.com/Yumina0789/Steward/main}"
UNINSTALL=0
PURGE=0
PY="$(command -v python3 || true)"
# 管道执行时 BASH_SOURCE 可能没有，退回 $0；再不行就当当前目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"

usage() {
  cat <<'EOF'
Steward 安装脚本：把面板装成宿主机上的 systemd 服务。

选项：
  --port N        监听端口（默认 8402）
  --bind IP       监听地址（默认 127.0.0.1，对外请交给反向代理或 SSH 隧道）
  --prefix DIR    安装目录（默认 /opt/steward）
  --data-dir DIR  数据目录（默认 /var/lib/steward，放 token 与审计日志）
  --token STR     指定 token（默认随机生成）
  --uninstall     停止并移除服务，保留数据与 token
  --purge         连数据目录一起删
  -h, --help      看这段
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2 ;;
    --bind) BIND="${2:?}"; shift 2 ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:?}"; shift 2 ;;
    --token) TOKEN="${2:?}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) UNINSTALL=1; PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" != "0" ]; then
  echo "需要 root：面板要调 systemctl / docker / 读 /proc 与 /var/log。" >&2
  exit 1
fi

if [ "$UNINSTALL" = "1" ]; then
  echo "==> 停止并移除 steward.service"
  systemctl disable --now steward 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  if [ "$PURGE" = "1" ]; then
    echo "==> 删除 $DATA_DIR 与 $PREFIX"
    rm -rf "$DATA_DIR" "$PREFIX"
  else
    echo "==> 数据保留在 $DATA_DIR（想删就加 --purge）"
  fi
  echo "完成。"
  exit 0
fi

if [ -z "$PY" ]; then
  echo "找不到 python3。Steward 只用标准库，装一个 python3 就行（apt install -y python3）。" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> 取源码"
for f in steward.py ui.html; do
  if [ -f "$SCRIPT_DIR/$f" ]; then
    cp -f "$SCRIPT_DIR/$f" "$WORK/$f"
  else
    curl -fsSL --retry 3 --connect-timeout 15 -H 'Cache-Control: no-cache' \
      "$REPO_RAW/$f" -o "$WORK/$f"
  fi
  [ -s "$WORK/$f" ] || { echo "拿不到 $f" >&2; exit 1; }
done

echo "==> 安装到 $PREFIX"
mkdir -p "$PREFIX" "$DATA_DIR"
chmod 700 "$DATA_DIR"
for f in steward.py ui.html; do
  # 留上一份：升级出问题能立刻回滚
  [ -f "$PREFIX/$f" ] && cp -f "$PREFIX/$f" "$PREFIX/$f.bak"
  install -m 0644 "$WORK/$f" "$PREFIX/$f"
done

if [ ! -s "$DATA_DIR/steward.token" ]; then
  if [ -n "$TOKEN" ]; then
    printf '%s' "$TOKEN" > "$DATA_DIR/steward.token"
  else
    "$PY" -c 'import secrets;print(secrets.token_urlsafe(24),end="")' > "$DATA_DIR/steward.token"
  fi
fi
chmod 600 "$DATA_DIR/steward.token"
TOKEN="$(cat "$DATA_DIR/steward.token")"

echo "==> 写 systemd 单元"
cat > "$UNIT" <<EOF
[Unit]
Description=Steward 服务器管理面板
Documentation=https://github.com/Yumina0789/Steward
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PY $PREFIX/steward.py --mode real --bind $BIND --port $PORT --data-dir $DATA_DIR --token-file $DATA_DIR/steward.token
Restart=always
RestartSec=3
User=root
# 面板本身就是半个 root 工具（要 systemctl / docker / 杀进程），下面这些只是顺手挡误伤：
# /usr 与 /boot 只读、禁提权、私有 /tmp。/etc 仍可写 —— ufw 要写 /etc/ufw，
# apt 要写 /var/lib/apt，这些都得留着。
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now steward
sleep 1
if ! systemctl is-active --quiet steward; then
  echo "!! 服务没起来，看日志：journalctl -u steward -n 50 --no-pager" >&2
  exit 1
fi

# 服务 active 不等于端口在听：面板要先建好采样器才会 bind。等它真的能连上再报成功。
PROBE_IP="$BIND"
[ "$PROBE_IP" = "0.0.0.0" ] && PROBE_IP="127.0.0.1"
printf '==> 等端口 %s:%s 就绪' "$PROBE_IP" "$PORT"
ready=0
for _ in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/$PROBE_IP/$PORT") 2>/dev/null; then
    exec 3<&- 2>/dev/null || true
    ready=1
    break
  fi
  printf '.'
  sleep 0.5
done
printf '\n'
if [ "$ready" != "1" ]; then
  echo "!! 端口没起来，看日志：journalctl -u steward -n 50 --no-pager" >&2
  exit 1
fi
echo "==> 服务在跑，端口已就绪"

cat <<EOF

Steward 装好了。

  本机打开：http://$BIND:$PORT/?token=$TOKEN
  纯 token ：$TOKEN（存在 $DATA_DIR/steward.token，权限 600）

  从你自己的电脑访问，先开隧道（最稳）：
      ssh -L $PORT:127.0.0.1:$PORT root@<这台机器的 IP>
      浏览器打开 http://127.0.0.1:$PORT/?token=$TOKEN

  想用域名就直接交给反向代理，别把 $BIND 改成 0.0.0.0：
  这是个能启停服务、杀进程、封 IP 的 root 面板，公网上只有 token 一道门。

  看日志：journalctl -u steward -f
  升级  ：重跑这个脚本（会自动留 .bak）
  卸载  ：bash install.sh --uninstall [--purge]
EOF
