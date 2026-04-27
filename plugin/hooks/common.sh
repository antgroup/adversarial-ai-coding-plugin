#!/bin/bash
# 公共配置，供各 hook 脚本 source 引用

LOG_DIR="$HOME/.claude/plugin_logs/code-sec-enhancement/logs"
LOG_FILE="$LOG_DIR/tqplugin.log"

mkdir -p "$LOG_DIR" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >>"$LOG_FILE"
}
