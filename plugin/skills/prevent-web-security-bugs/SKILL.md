---
name: prevent-web-security-bugs
description: >
  当用户需要编写或修改 Web 后端代码时，应当使用此技能。包括但不限于：
  "写个接口"、"新增 API"、"实现登录功能"、"添加用户查询"、"文件上传接口"、
  "数据库查询"、"调用第三方 API"、"写个 Controller"、"REST 接口开发"、
  "添加权限校验"、"数据导出功能"。
  即使用户没有提到"安全"或"漏洞"，只要涉及 Web 接口、数据访问、用户输入处理、
  外部资源调用等场景，都应触发此技能。
---

# 安全代码生成规范

## 工作流程

按以下三步执行安全代码生成。安全漏洞的修复成本随开发阶段推进急剧上升——在代码生成阶段消除漏洞成本最低，上线后修复可能需要紧急发布、数据迁移甚至承担安全事故损失。

### 第一步：识别安全风险

逐条分析用户需求，对照下表判断哪些风险类型适用于当前场景。

| 风险类型 | 触发场景 | 参考文档 |
|---|---|---|
| Query Language 注入 | 字符串拼接构造 SQL/HQL/NoSQL 查询 | `references/prevent-ql-injection.md` |
| 越权访问 | 按资源 ID 查询或修改数据；接口访问控制 | `references/prevent-unauthorized-access.md` |
| SSRF | 服务端发起 HTTP 请求，目标地址来自用户输入 | `references/prevent-ssrf.md` |
| 路径遍历 | 文件操作，路径由用户输入控制 | `references/prevent-path-traversal.md` |
| OS 命令执行 | 执行系统命令，命令内容包含用户输入 | `references/prevent-os-command-execution.md` |
| 代码执行 | 动态执行脚本或表达式，内容来自用户输入 | `references/prevent-code-execution.md` |
| 模板注入 | 模板引擎渲染用户可控内容 | `references/prevent-template-injection.md` |
| 反序列化 | 反序列化用户输入或解析 JSON | `references/prevent-deserialization.md` |
| 凭据硬编码 | 敏感信息直接硬编码到代码中 | `references/prevent-hardcoded-credentials.md` |
| XXE | XML 解析 | `references/prevent-xxe.md` |

### 第二步：查阅安全编码规范

对第一步中识别出的每个风险类型，读取对应的参考文档，理解漏洞根因、防范模式和安全 API 用法。完成所有文档阅读后再进入第三步。

### 第三步：生成符合安全规范的代码

在完整理解安全规范后，按以下原则完成用户需求：

- **默认安全**：优先使用参数化查询、白名单校验、安全 API 等内置防护机制
- **零信任输入**：所有来自 HTTP 请求、外部接口、配置文件的数据一律视为不可信，使用前完成格式校验、类型转换或参数化处理
- **显式鉴权**：每个需要权限的操作在当前方法内显式执行权限校验
- **失败安全**：权限校验或输入验证失败时默认拒绝操作并返回明确错误响应

---

## 参考资源

### 参考文档
- **`references/prevent-ql-injection.md`** — SQL/NoSQL 注入防范
- **`references/prevent-unauthorized-access.md`** — 越权访问防范
- **`references/prevent-ssrf.md`** — SSRF 防范
- **`references/prevent-path-traversal.md`** — 路径遍历防范
- **`references/prevent-os-command-execution.md`** — OS 命令执行防范
- **`references/prevent-code-execution.md`** — 代码执行防范
- **`references/prevent-template-injection.md`** — 模板注入防范
- **`references/prevent-deserialization.md`** — 反序列化防范
- **`references/prevent-hardcoded-credentials.md`** — 凭据硬编码防范
- **`references/prevent-xxe.md`** — XXE 防范