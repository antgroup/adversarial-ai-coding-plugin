---
name: prevent-js-security-bugs
description: 当用户需要编写、重构或修改 JavaScript/TypeScript 代码时，必须激活本技能。激活后，先执行威胁分析，再查阅对应安全规范文档，最后生成符合安全编码标准的代码，确保不引入已知安全漏洞。
---

# 安全代码生成规范

## 技能概述

本技能的目标是：**在代码生成阶段消除安全漏洞，而非依赖事后审查**。

当用户需要编写、重构或修改 JavaScript/TypeScript 代码时，必须先完成威胁识别和规范查阅，再生成代码。禁止跳过安全分析步骤。

## 触发条件

满足以下**任意一条**时，必须激活本技能：

- 编写、重构或修改 JavaScript/TypeScript 代码。

## 工作流程

**必须严格按顺序执行以下三步，不得跳过任何步骤。**

### 第一步：识别安全风险

逐条分析用户需求，对照下表判断哪些风险类型适用于当前场景。**每一个适用的风险类型都必须处理，不得遗漏。**

| 风险类型 | 典型场景 | 对应参考文档 |
|---|---|---|
| Query Language 注入 | 拼接 SQL/HQL/NoSQL 查询语句；使用用户输入构造查询条件 | `references/prevent-ql-injection.md` |
| OS 命令注入 | 调用 `child_process.exec`、`execSync`、`spawn` 等执行系统命令时，命令字符串或参数包含用户输入 | `references/prevent-os-command-execution.md` |
| 代码注入 | 使用 `eval`、`new Function`、`setTimeout(string)` 执行非字面量字符串；使用非字面量路径动态 `require()`；可能导致 RCE 或任意文件读取 | `references/prevent-code-injection.md` |
| 原型链污染 | 对对象进行递归合并、深拷贝、属性赋值时，键名来自用户输入（如 `__proto__`、`constructor`、`prototype`） | `references/prevent-prototype-pollution.md` |
| XSS（跨站脚本） | 将用户输入直接插入 DOM（`innerHTML`、`document.write`、`dangerouslySetInnerHTML`）；在服务端渲染时未转义输出到 HTML 模板 | `references/prevent-xss.md` |
| 路径遍历 | 文件读取/写入/下载，路径由用户输入拼接（如 `path.join(baseDir, userInput)`），可能跨越根目录访问任意文件 | `references/prevent-path-traversal.md` |
| SSRF（服务端请求伪造） | 服务端发起 HTTP 请求时，目标 URL 或主机名由用户输入控制，可能访问内网服务或云元数据接口 | `references/prevent-ssrf.md` |
| 不安全反序列化 | 使用 `node-serialize`、`serialize-javascript` 等库反序列化用户提供的数据，可能导致任意代码执行 | `references/prevent-deserialization.md` |
| 弱随机数 | 使用 `Math.random()` 或 `crypto.pseudoRandomBytes()` 生成 session ID、token、nonce、密钥等安全敏感值 | `references/prevent-weak-random.md` |
| PostMessage Origin 校验缺失 | 使用 `window.addEventListener('message', ...)` 接收跨窗口消息时未校验 `event.origin`；发送消息时使用通配符 `'*'` | `references/prevent-postmessage-origin.md` |
| 时序攻击 | 使用 `===`、`!==` 比较 HMAC 签名、API Key、session token、密码重置 token 等安全敏感字符串 | `references/prevent-timing-attack.md` |
| ReDoS（正则表达式拒绝服务） | 使用 `new RegExp(userInput)` 构造动态正则；正则模式包含嵌套量词（`(a+)+`）或重叠交替（`(a\|aa)+`），可导致灾难性回溯阻塞事件循环 | `references/prevent-redos.md` |
| Buffer 安全问题 | 使用已废弃的 `new Buffer(size)`（内存未初始化）；`Buffer.allocUnsafe()` 结果未立即填充；Buffer 读写方法传入 `noAssert=true` 跳过边界检查 | `references/prevent-buffer-issues.md` |
| 不安全传输 | 通过 HTTP（非 HTTPS）加载外部脚本/样式；服务端使用 `http` 模块请求外部 API；动态 URL 未校验协议 | `references/prevent-insecure-transport.md` |
| 硬编码凭证 | API Key、密码、JWT 密钥、私钥等敏感信息直接写入源代码或被 Git 追踪的配置文件 | `references/prevent-hardcoded-secrets.md` |


### 第二步：查阅安全编码规范

对第一步中**每一个**识别出的风险类型，必须读取对应的参考文档，理解该类漏洞的根因、防范模式和安全 API 用法，然后再进入第三步。

### 第三步：完成用户需求

在完整理解安全规范后，按以下原则，完成用户需求：

- **默认安全**：优先使用参数化查询、白名单校验、安全 API 等内置防护机制，而非在危险写法上叠加过滤
- **零信任输入**：所有来自 HTTP 请求、外部接口、URL 参数的数据，一律视为不可信，必须在使用前完成校验或转义处理
- **失败安全**：权限校验或输入验证失败时，默认拒绝操作并返回明确的错误响应，不得静默放行
- **运行时验证**：TypeScript 类型检查仅在编译期生效，对外部输入必须使用运行时 schema 验证（如 `zod`、`class-validator`）
- **原型隔离**：处理来自外部的 JSON 对象时，使用 `Object.create(null)` 或冻结原型，防止原型链污染
- **最小权限**：文件操作、子进程调用、网络请求，遵循最小权限原则，明确限定允许的范围（路径前缀、命令白名单、域名白名单）
