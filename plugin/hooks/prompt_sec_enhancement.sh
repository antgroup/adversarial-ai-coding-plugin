#!/bin/bash
# Claude Code hook 脚本：读取 stdin 的 JSON 输入，传递给 Python 脚本处理

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

log "prompt_sec_enhancement.sh start"

# 防止递归：当 CLAUDE_CODE_ENTRYPOINT 不是 "cli" 时，说明本次调用来自
# claude_agent_sdk（值为 sdk-py）等内部调用，而非用户直接输入，直接退出避免无限循环。
if [ "$CLAUDE_CODE_ENTRYPOINT" != "cli" ]; then
    log "非用户直接调用(CLAUDE_CODE_ENTRYPOINT=${CLAUDE_CODE_ENTRYPOINT})，跳过处理"
    exit 0
fi

# 鲁棒性保障：无论任何原因退出（ERR 信号、EXIT 信号），均静默 exit 0，不阻断 Claude Code 执行
exec 2>>"$LOG_FILE"
trap 'exit 0' EXIT ERR

PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON_CMD=""

# 按优先级依次检测可用的 Python 3 命令
# 1. 优先检测具体版本（python3.14 → python3.10）
for PYTHON_VERSION_CMD in python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$PYTHON_VERSION_CMD" >/dev/null 2>>"$LOG_FILE"; then
        PYTHON_CMD="$PYTHON_VERSION_CMD"
        log "${PYTHON_VERSION_CMD} command found, use it as PYTHON_CMD"
        break
    fi
done

# 2. 若未找到具体版本，检测通用的 python3 命令
if [ -z "$PYTHON_CMD" ]; then
    if command -v python3 >/dev/null 2>>"$LOG_FILE"; then
        PYTHON_CMD="python3"
        log "python3 command found"
    elif command -v python >/dev/null 2>>"$LOG_FILE"; then
        # python 命令存在，检查其实际版本是否为 Python 3
        PYTHON_MAJOR_VERSION=$(python -c "import sys; print(sys.version_info.major)" 2>>"$LOG_FILE") || PYTHON_MAJOR_VERSION=""
        if [ "$PYTHON_MAJOR_VERSION" = "3" ]; then
            PYTHON_CMD="python"
        else
            log "no python3, exit"
            exit 0
        fi
    else
        log "no python or python3, exit"
        exit 0
    fi
fi

log "python_cmd=${PYTHON_CMD}"

# 检查 .venv 是否存在，不存在则创建并安装依赖
if [ ! -d "$PLUGIN_DIR/.venv" ]; then
    "$PYTHON_CMD" -m venv "$PLUGIN_DIR/.venv" >>"$LOG_FILE" 2>&1 || exit 0
    "$PLUGIN_DIR/.venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        >>"$LOG_FILE" 2>&1 || { rm -rf "$PLUGIN_DIR/.venv"; log "pip install 失败，已清理 .venv，下次启动将重试"; exit 0; }
fi

log "plugin_dir=${PLUGIN_DIR}"
log "venv install success"

# 激活 venv 中的 Python 环境
source "$PLUGIN_DIR/.venv/bin/activate" >>"$LOG_FILE" 2>&1 || exit 0
PYTHON_CMD="$PLUGIN_DIR/.venv/bin/python"
log "venv activated, python_cmd=${PYTHON_CMD}"

# 读取 stdin 的 JSON 输入
# 使用 printf '%s' 避免 echo 对特殊字符（如 -n、反斜杠）的异常处理
INPUT=$(cat 2>>"$LOG_FILE") || INPUT=""

# 如果输入为空，直接退出
if [ -z "$INPUT" ]; then
    exit 0
fi

log "start run prompt_sec_enhancement.py"
# 调用 Python 脚本，将 JSON 输入通过 stdin 传递
printf '%s' "$INPUT" | "$PYTHON_CMD" "$SCRIPT_DIR/prompt_sec_enhancement.py" 2>>"$LOG_FILE" || true
