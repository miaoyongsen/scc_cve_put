#!/usr/bin/env bash
# SCC_CVE updater; separate filename prevents a pull conflict with local amiao.sh.
set -euo pipefail

ROOT=/home/msocadmin/amiaotest/scc_cve_put
BACKEND="$ROOT/backend"
PID_FILE="$ROOT/.scc_cve.pid"
LOG_FILE="$ROOT/logs/scc_cve.log"
cd "$ROOT"

echo "[1/5] 拉取最新代码..."
git -c url."https://ghfast.top/https://github.com/".insteadOf="https://github.com/" pull --ff-only origin main
echo "Git 更新成功: $(git rev-parse --short HEAD)"

echo "[2/5] 安装依赖并编译前端..."
# install.sh contains npm install and npm run build; do not repeat these steps.
bash "$ROOT/install.sh"

echo "[3/5] 编译检查 Python 代码..."
"$BACKEND/.venv/bin/python" -m compileall -q "$BACKEND/app"

# Use the same port as start.sh.
PORT=8000
if [[ -f "$BACKEND/.env" ]]; then
  PORT=$(set -a; source "$BACKEND/.env"; echo "$PORT")
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "Invalid PORT in backend/.env" >&2
  exit 1
fi

# Only match our own uvicorn processes with cwd equal to this repository's backend.
is_our_process() {
  local pid="$1" cmd cwd owner
  [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 1
  cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)
  [[ "$cwd" == "$BACKEND" ]] || return 1
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
  [[ "$cmd" == *"uvicorn"* && "$cmd" == *"app.core:app"* ]] || return 1
  owner=$(stat -c %u "/proc/$pid" 2>/dev/null || true)
  [[ "$owner" == "$(id -u)" ]]
}

echo "[4/5] 停止旧版 SCC_CVE 服务..."
pids=()
if [[ -r "$PID_FILE" ]]; then
  old_pid=$(cat "$PID_FILE")
  if is_our_process "$old_pid"; then pids+=("$old_pid"); fi
fi
for entry in /proc/[0-9]*; do
  [[ -d "$entry" ]] || continue
  candidate=$(basename "$entry")
  if is_our_process "$candidate"; then
    found=0
    for pid in "${pids[@]}"; do
      if [[ "$pid" == "$candidate" ]]; then found=1; break; fi
    done
    if ((found == 0)); then pids+=("$candidate"); fi
  fi
done
if (("${#pids[@]}" > 0)); then
  echo "Stopping PID(s): ${pids[*]}"
  for pid in "${pids[@]}"; do
    if is_our_process "$pid"; then kill -TERM "$pid"; fi
  done
  for ((i=0;i<20;i++)); do
    alive=0
    for pid in "${pids[@]}"; do
      if is_our_process "$pid"; then alive=1; break; fi
    done
    if ((alive == 0)); then break; fi
    sleep 1
  done
  for pid in "${pids[@]}"; do
    if is_our_process "$pid"; then
      echo "旧进程 $pid 未退出，强制停止"
      kill -KILL "$pid"
    fi
  done
else
  echo "未发现旧版 SCC_CVE 进程"
fi
rm -f "$PID_FILE"

echo "[5/5] 后台启动新版本..."
mkdir -p "$ROOT/logs"
nohup bash "$ROOT/start.sh" >> "$LOG_FILE" 2>&1 < /dev/null &
new_pid=$!
echo "$new_pid" > "$PID_FILE"

ready=0
for ((i=0;i<20;i++)); do
  if ! kill -0 "$new_pid" 2>/dev/null; then
    echo "新进程已退出，请检查：$LOG_FILE" >&2
    tail -n 50 "$LOG_FILE" >&2 || true
    exit 1
  fi
  if "$BACKEND/.venv/bin/python" - "$PORT" <<'PY' >/dev/null 2>&1
import sys
from urllib.request import urlopen
try:
    with urlopen("http://127.0.0.1:%s/openapi.json" % sys.argv[1], timeout=2) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
  then
    ready=1
    break
  fi
  sleep 1
done

if ((ready == 0)) || ! is_our_process "$new_pid"; then
  echo "新进程未通过启动检查：$LOG_FILE" >&2
  tail -n 50 "$LOG_FILE" >&2 || true
  exit 1
fi
echo "更新完成: $(git rev-parse --short HEAD)"
echo "PID=$new_pid PORT=$PORT"
echo "日志: $LOG_FILE"
