#!/usr/bin/env bash
cd "$(dirname "$0")"

if systemctl cat lan-blog.service >/dev/null 2>&1; then
    sudo systemctl stop lan-blog
    echo "已停止 lan-blog 服务"
    exit 0
fi

if [ -f logs/gunicorn.pid ]; then
    kill "$(cat logs/gunicorn.pid)" 2>/dev/null && echo "服务已停止" || echo "进程不存在或已退出"
    rm -f logs/gunicorn.pid
else
    echo "未发现 pid 文件，服务可能未在运行"
fi
