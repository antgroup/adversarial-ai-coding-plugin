#!/usr/bin/env python3
"""
Claude Code 安全增强插件 - 核心逻辑

当用户提交 prompt 时，通过 Claude Agent SDK 创建 Agent 判断用户的 prompt
是否为代码生成请求。如果是，分析可能存在的安全风险，并将安全提示追加到
用户的 prompt 后面，作为 additionalContext 返回给 Claude Code。
"""

import json
import logging
import os
import re
import sys
from pathlib import Path




# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
def setup_logger() -> logging.Logger:
    """配置日志，输出到 ~/.config/claude-code-plugin/code-sec-enhancement/logs/tq_plugin.log"""
    log_dir = Path("~/.claude/plugin_logs/code-sec-enhancement/logs").expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "tqplugin.log"

    logger = logging.getLogger("tq_plugin")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


logger = setup_logger()
logger.info("prompt_sec_enhancement.py start")

import anyio
from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock
# ---------------------------------------------------------------------------
# 配置读取
# ---------------------------------------------------------------------------
def load_settings_from_file(file_path: str) -> dict:
    """从指定的 JSON 文件中读取配置"""
    path = Path(file_path).expanduser()
    if not path.exists():
        logger.warning("配置文件 %s 不存在", file_path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("读取配置文件 %s 失败: %s", file_path, exc)
        return {}

# 验证cc-Switch支不支持，已验证，支持。
def get_config() -> dict:
    """
    按优先级读取配置：环境变量 > .claude/settings.json > ~/.claude/settings.json

    需要读取的配置项：
    - base_url: API 基础地址
    - AUTH_TOKEN: 认证令牌
    - model: 使用的模型名称
    """
    # 1. 从 ~/.claude/settings.json 读取（最低优先级）
    global_settings = load_settings_from_file("~/.claude/settings.json")

    # 2. 从项目级 .claude/settings.json 读取
    project_settings = load_settings_from_file(os.path.join(os.getcwd(), ".claude/settings.json"))

    # 合并配置，项目级覆盖全局
    merged = {}
    config_keys=("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL","ANTHROPIC_MODEL","ANTHROPIC_DEFAULT_HAIKU_MODEL",
                "ANTHROPIC_DEFAULT_SONNET_MODEL","ANTHROPIC_DEFAULT_OPUS_MODEL","ANTHROPIC_SMALL_FAST_MODEL")
    for key in config_keys:
        value = global_settings.get(key)
        if project_settings.get(key):
            value = project_settings.get(key)
        # 环境变量覆盖（最高优先级）
        env_value = os.environ.get(key)
        if env_value:
            value = env_value
        if value:
            merged[key] = value

    return merged


# ---------------------------------------------------------------------------
# 安全分析 Agent
# ---------------------------------------------------------------------------
SECURITY_ANALYSIS_SYSTEM_PROMPT = """你是一个需求分类专家。你极其擅长判断用户的prompt是否为代码生成请求。

1. 判断用户的 prompt 是否是一个代码生成请求（例如：编写代码、创建函数、实现功能、修复 bug、重构代码等）。
2. 以下不是代码生成请求（例如：与代码无关的话题、纯粹的问答、解释概念、查看文件、询问代码实现等）。
3. 在判断用户prompt是否为代码生成请求后，请严格按照如下格式输出，以提交你的结论：
<result>
{"is_code_generation": true|false}
</result>

"""


async def analyze_prompt_security(user_prompt: str, config: dict) -> str:
    """
    使用 Claude Agent SDK 创建 Agent，分析用户 prompt 的安全风险。

    返回安全提示文本，如果不是代码生成请求则返回空字符串。
    """
    os.environ.pop("CLAUDECODE", None)

    analysis_prompt = f"请分析以下用户 prompt 是否为代码生成请求：\n```{user_prompt}```"


    options = ClaudeAgentOptions(system_prompt=SECURITY_ANALYSIS_SYSTEM_PROMPT, max_turns=1,env=config)

    response_text = ""
    try:
        async for message in query(prompt=analysis_prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        response_text += block.text
    except Exception as exc:
        logger.error("调用 Claude Agent SDK 分析安全风险失败: %s", exc)
        return ""

    logger.info("Agent 原始响应: %s", response_text)

    # 解析 Agent 返回的 JSON
    try:
        # 使用正则表达式提取 <result> 和 </result> 之间的内容
        pattern = r"<result>\s*(.*?)\s*</result>"
        match = re.search(pattern, response_text, re.DOTALL)

        if not match:
            logger.warning("未找到 <result> 标签，原始响应: %s", response_text)
            return ""

        json_text = match.group(1).strip()
        logger.info("提取到的 JSON 内容: %s", json_text)

        return json_text

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.warning("解析 Agent 响应 JSON 失败: %s, 原始响应: %s", exc, response_text)

    return ""


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
async def async_main():
    """异步主函数"""
    # 从 stdin 读取 hook 输入的 JSON
    raw_input = sys.stdin.read()
    logger.info("收到 hook 输入: %s", raw_input)

    try:
        hook_input = json.loads(raw_input)
    except json.JSONDecodeError as exc:
        logger.error("解析 hook 输入 JSON 失败: %s", exc)
        sys.exit(0)

    user_prompt = hook_input.get("prompt", "")
    if not user_prompt.strip():
        logger.info("用户 prompt 为空，跳过处理")
        sys.exit(0)

    # 第二道防递归保险：正常情况下 prompt_sec_enhancement.sh 已通过
    # CLAUDE_CODE_ENTRYPOINT != "cli" 提前拦截了 sdk-py 的递归调用。
    # 此处作为兜底，防止 sh 层失效时 py 层仍能阻断无限循环。
    if user_prompt.startswith("请分析以下用户 prompt 是否为代码生成请求："):
        logger.info("检测到插件内部递归调用，跳过处理")
        sys.exit(0)

    logger.info("用户 prompt: %s", user_prompt)

    # 读取配置
    config = get_config()

    # 打印配置
    for key, value in config.items():
        if key == "ANTHROPIC_AUTH_TOKEN" or key == "ANTHROPIC_API_KEY":
            value = "***"
        logger.info("%s: %s", key, value)


    # 调用 Agent 分析安全风险
    agent_result = await analyze_prompt_security(user_prompt, config)

    if agent_result=="":
        logger.info("Agent运行Error，无安全提示需要添加，正常放行")
        sys.exit(0)
    else:
        try:
            is_code_generation = json.loads(agent_result).get("is_code_generation", False)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("解析 is_code_generation 失败: %s, agent_result: %s", exc, agent_result)
            sys.exit(0)
        if not is_code_generation:
            logger.info("用户 prompt 不是代码生成请求，跳过处理")
            sys.exit(0)
        else:
            logger.info("用户 prompt 是代码生成请求，需要添加安全提示")

            # 构造输出 JSON，将安全提示作为 additionalContext 添加
            additional_context = (
                "\n\n[安全提示]\n"
                "为了尽可能在代码生成阶段消除安全漏洞，请根据实际情况，积极调用 prevent-* skills（如 prevent-iac-security-bugs、 prevent-web-security-bugs、prevent-c-cpp-security-bugs 等）。\n\n"
                "[安全审查要求]\n"
                "当你完成本次任务所有代码修改后（即整个任务结束前），必须调用 `post-edit-security-review` skill，"
                "对本次修改的全部代码进行安全漏洞审查，如发现漏洞则修复。"
            )


            output = {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": additional_context,
                }
            }

            output_json = json.dumps(output, ensure_ascii=False)
            logger.info("输出安全增强上下文: %s", output_json)

            # 输出 JSON 到 stdout，Claude Code 会读取并处理
            print(output_json)


def main():
    """同步入口"""
    try:
        anyio.run(async_main)
    except Exception as exc:
        logger.error("插件执行异常: %s", exc, exc_info=True)
        sys.exit(0)


if __name__ == "__main__":
    main()