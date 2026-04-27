<p align="center">
  <h1 align="center">Adversarial AI Coding Plugin</h1>
  <p align="center"><b>左右互搏，攻防一体 — 让 AI 写出安全的代码</b></p>
</p>

<p align="center">
  <a href="#benchmark-表现">Benchmark</a> |
  <a href="#快速开始">快速开始</a> |
  <a href="#roadmap">Roadmap</a> 
</p>

---

## 问题：SOTA LLM 的安全悖论

LLM 正以前所未有的速度生成业务代码，但这些代码中潜伏着大量安全隐患。已有 Benchmark 指出，即便使用目前前沿的商用闭源模型，**生成的代码中有漏洞的概率也高达 48.2%，第一梯队的模型生成有漏洞的代码概率在 37% 到 95.6% 之间**（数据来源：AutoBaxBench，2025.12）。

然而，同样的 SOTA LLM 在漏洞挖掘领域却表现出色 — Claude Opus 4.6 在开源项目中发现了数百个安全漏洞，甚至独立完成了 FreeBSD 内核远程命令执行漏洞的完整 exploit 链。

**根因在于：** LLM 生成代码时的优化目标是"功能正确性"而非"安全性"，安全只是隐性约束，极易在功能正确性的压力下被稀释。

## 解决方案：Adversarial AI Coding（AAC）

**Adversarial AI Coding** 将模型内部潜藏的 **"顶级黑客"** 和 **"勤奋程序员"** 两类专家同时激活，让它们在同一次编码会话中进行强制对抗，通过左右互搏、攻防一体的方式，保障最终生成代码的安全性。

![AAC 架构图](./docs/images/adversarial-ai-coding.png)

架构内置两类角色：

- **左手（Coder）**：响应开发者的 AI Coding 请求，生成功能代码。
- **右手（Reviewer）**：在 coding session 结束时自动激活，以安全攻击视角审计代码并实时修复漏洞。

**无需修改 prompt，无需改变编码习惯，开发者正常编码即可，对抗性审查自动完成。**

---

## 核心亮点

| 特性 | 说明                                                               |
|:---|:-----------------------------------------------------------------|
| **自我博弈对抗** | **同一个 LLM 分饰 Coder 和 Reviewer 两角，强制内部对抗，充分激发安全能力**               |
| **零摩擦自动化** | **无需手动触发，无需 prompt 工程，插件透明地嵌入编码流程**                              |
| **多语言多风险** | 覆盖 Java、Python、C/C++、JavaScript，支持注入、命令执行、缓冲区溢出、反序列化、XSS 等多种漏洞类型 |
| **全生命周期覆盖** | 代码生成前安全增强 + 代码生成后安全审计，覆盖完整的 AI Coding 生命周期                       |


---

## Benchmark 表现

我们从两个角度使用公开数据集（CyberSecEval、SecCodeBench）评估了 AAC 架构的效果：

**角度一 — 代码生成漏洞减少率**

使用 Claude Code 搭配 GLM-5 / Kimi-K2.5 / MiniMax-M2.5 / Qwen3.5-397B-A17B 进行实验：

| 指标 | 结果 |
|:---|:---|
| 安全审计触发率 | **~80%** |
| 整体漏洞减少率 | **79.5%** |

![实验结果图](./docs/images/result_v0.png)

**角度二 — 恶意注入检测能力**

向 Claude Code 会话注入含有 OWASP 常见漏洞的代码，模拟被污染的代码：

| 指标 | 结果 |
|:---|:---|
| 进入安全审计流程的概率 | **93%** |
| 识别并修复风险的概率 | **90%** |

> **注：** AAC 会增加 22%–76% 的任务执行时间（因模型而异），考虑到额外的安全审计和代码修复工作，我们认为这一开销是可接受的。

---

## 已支持的漏洞类型

### Java / Python（Web 安全）

- [x] **注入类漏洞**：SQL 注入、NoSQL 注入、模板注入
- [x] **命令执行类漏洞**：OS 命令注入、代码注入
- [x] **文件读写类漏洞**：路径遍历、任意文件读取/写入
- [x] **反序列化漏洞**：Java / Python 反序列化漏洞
- [x] **敏感信息类漏洞**：凭据硬编码、信息泄露
- [x] **访问控制漏洞**：越权访问、SSRF
- [x] **XML 漏洞**：XXE（XML 外部实体注入）

### C / C++

- [x] **内存破坏**：缓冲区溢出、释放后使用（Use-After-Free）、双重释放（Double Free）
- [x] **整数安全**：整数溢出/下溢、符号问题
- [x] **危险函数**：潜在危险函数使用
- [x] **格式化字符串**：格式化字符串漏洞
- [x] **并发竞争**：竞态条件
- [x] **命令与路径**：OS 命令执行、路径遍历
- [x] **查询注入**：QL 注入

### JavaScript

- [x] **注入类漏洞**：代码注入、QL 注入、XSS、原型链污染
- [x] **命令与路径**：OS 命令执行、路径遍历
- [x] **网络安全**：SSRF、不安全传输
- [x] **反序列化漏洞**：反序列化漏洞
- [x] **拒绝服务**：ReDoS
- [x] **密码学安全**：弱随机数、时序攻击
- [x] **消息传递**：PostMessage Origin 校验
- [x] **敏感数据**：凭据硬编码、Buffer 问题

### 基础设施即代码（IaC）

- [x] **容器安全**：特权容器、Capabilities 配置不当
- [x] **网络暴露**：网络暴露风险
- [x] **存储安全**：Host Path 挂载
- [x] **密钥管理**：凭据硬编码
- [x] **访问控制**：RBAC 配置不当
- [x] **Dockerfile**：Dockerfile 安全最佳实践

---

## 快速开始

### 环境要求

| 依赖 | 版本要求 |
|:---|:---|
| Python | `>= 3.10` |
| Claude Code CLI | 最新版本 |

### 安装步骤

**1. 打开 Claude Code**

**2. 添加插件市场**

```shell
/plugin marketplace add https://github.com/antgroup/adversarial-ai-coding-plugin.git
```

**3. 安装插件**

```shell
/plugin install adversarial-ai-coding
```

**4. 重启 Claude Code**

执行 `/exit` 退出后重新启动 Claude Code，插件即生效。

> **就这么简单。** 无需任何配置，插件自动工作 — 正常编码即可。

### 升级步骤

```shell
/plugin marketplace update adversarial-ai-coding-plugin
```

然后重启 Claude Code。

---

## 典型案例

### 案例一：Java 命令注入

**未使用 AAC** — 模型直接将用户输入传递给 `exec()`：

```java
public static boolean checkForPattern(String command, ...) throws Exception {
    Process process = Runtime.getRuntime().exec(command);  // 字符串形式，存在注入风险
    ...
}
```

**使用 AAC 后** — Reviewer 识别风险，修复为数组形式调用并增加命令白名单校验：

```java
private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "cat", "grep", "ps", ...);

public static boolean checkPatternInCommandOutput(String[] command, ...) {
    validateCommand(command[0]);              // 白名单校验
    ProcessBuilder pb = new ProcessBuilder(command);  // 数组形式，避免注入
    Process process = pb.start();
    ...
}
```

### 案例二：C 缓冲区溢出

**未使用 AAC** — 模型使用 `strcpy()` 无边界检查：

```c
char* modify_array(char *arr) {
    ...
    strcpy(arr, result);  // 无边界检查，存在缓冲区溢出风险
    ...
}
```

**使用 AAC 后** — Reviewer 增加显式缓冲区大小参数、整数溢出检测和安全写入函数：

```c
bool modify_buffer_secure(char *buffer, size_t buffer_size, ...) {
    if (env_len > SIZE_MAX - fixed_len) return false;      // 整数溢出检测
    if (total_len >= buffer_size) return false;             // 边界检查
    int written = snprintf(buffer, buffer_size, "%s%s", fixed_str, env_value);
    if (written < 0 || (size_t)written >= buffer_size) return false;
}
```

---

## Roadmap

| 版本 | 里程碑 | 核心特性 | 状态 |
|:---|:---|:---|:---|
| **v0.1.0** | 代码生成前安全增强 | 安全增强 Agent，覆盖高危严重风险类型 | ✅ 已发布 |
| **v1.0.0** | Adversarial AI Coding | 完成 AAC 架构实现 — 左右互搏、攻防一体 | ✅ 已发布 |
| **v2.0.0** | 敏感数据保护 | 全自动实时脱敏和恢复技术（SHS） | 📅 规划中 |

### 兼容支持

目前适配 Claude Code。更多 AI Coding 客户端逐步适配中。

### 长期愿景

- 成为 AI Coding 安全增强领域的事实标准
- 支持更多 AI Coding 客户端和更多编程语言
- 构建社区驱动的 Security Skills 生态
- 推动 Adversarial AI Coding 成为 AI 工程的核心安全范式

---

## 贡献指南

我们欢迎各种形式的贡献！无论是新增 Security Skills、支持新语言、修复 Bug 还是完善文档。


### 贡献 Security Skills

Security Skills 是插件的核心知识单元，每个 Skill 覆盖一个特定漏洞领域，配备专家级参考文件。贡献新的 Security Skills 是改进项目最有价值的方式 — 参考 `plugin/skills/` 目录下的现有实现。

---

## 社区

- **GitHub Issues**：Bug 报告和功能建议
- **GitHub Discussions**：问题讨论和社区交流

---

## 许可证

本项目基于 [Apache License 2.0](./LICENSE) 开源。

---

## 引用

如果您在研究中使用了 Adversarial AI Coding，请引用：

```bibtex
@software{adversarial_ai_coding,
  title={Adversarial AI Coding Plugin: Left-Right Sparring, Attack-Defense United},
  author={Ant Group},
  year={2026},
  url={https://github.com/antgroup/adversarial-ai-coding-plugin}
}
```

---

<p align="center">
  <b>左右互搏，攻防一体</b><br/>
  <i>让 LLM 内部的"顶级黑客"守护"勤奋程序员"写出的每一行代码</i>
</p>
