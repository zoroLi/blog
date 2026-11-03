#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PORT="${PORT:-8000}"
mkdir -p logs

if systemctl cat lan-blog.service >/dev/null 2>&1; then
    sudo systemctl start lan-blog
    IP="$(hostname -I | awk '{print $1}')"
    echo "已通过 systemd 启动：http://${IP}:${PORT}"
    exit 0
fi

if [ -f logs/gunicorn.pid ] && kill -0 "$(cat logs/gunicorn.pid)" 2>/dev/null; then
    echo "服务已在运行 (pid $(cat logs/gunicorn.pid))"
    exit 0
fi

.venv/bin/gunicorn \
    -w 2 --threads 4 \
    -b "0.0.0.0:${PORT}" \
    --access-logfile logs/access.log \
    --error-logfile logs/error.log \
    --pid logs/gunicorn.pid \
    --daemon app:app

IP="$(hostname -I | awk '{print $1}')"
echo "已启动：http://${IP}:${PORT}"
