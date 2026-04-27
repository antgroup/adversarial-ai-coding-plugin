---
name: post-edit-security-review
description: >
  在整个编码任务完成后（所有文件修改均已完成、即将结束本次回复时），必须主动调用此技能执行一次安全审查。
  满足以下任意一条时必须激活：
  (1) 完成了代码新增、功能实现、bug 修复或重构，即将输出最终回复；
  (2) 使用了 Write/Edit/NotebookEdit 等工具修改了源代码文件。
  不要在每次写入单个文件后调用，整个任务的最后一步调用一次。
  不要在仅回答问题、阅读文件、执行 git 操作时激活。
  此技能是代码交付前的最后一道安全防线，聚焦于发现并修复本次任务引入的安全漏洞。
---

# 代码修改后安全审查规范

## 技能目标

**在代码变更完成后立即进行安全扫描，发现并修复已引入的安全漏洞，确保交付的代码不含已知安全风险。**

代码修改完成后是拦截安全漏洞的关键时机——在代码合并或上线前发现并修复漏洞，远比上线后应急响应的代价低。

---

## 工作流程

按以下四步执行代码安全审查。**每一步均必须执行，不可跳过。**

---

### 第一步：识别本次变更的代码范围

明确本次修改涉及的所有文件和代码片段：

- 列出所有被新增或修改的文件路径
- 标注每个文件中变更的核心逻辑（新增函数、修改逻辑、新增依赖等）
- 判断变更涉及的技术栈（Web 后端 / C/C++ 系统代码 / JavaScript/TypeScript / IaC 基础设施配置 / 其他）

---

### 第二步：按技术栈扫描安全漏洞

根据第一步识别的技术栈，逐类检查下列安全风险。**对每一个适用的风险类型，读取对应的参考文档后再执行检查。**

#### 2A：Web 后端代码安全检查

适用场景：变更涉及 Web 接口、数据库访问、用户输入处理、文件操作、外部 HTTP 请求、命令执行、模板渲染、XML 解析、反序列化、认证鉴权。

| 风险类型 | 检查要点 | 参考文档 |
|---|---|---|
| Query Language 注入 | 是否存在字符串拼接构造 SQL/HQL/NoSQL | `../prevent-web-security-bugs/references/prevent-ql-injection.md` |
| 越权访问 | 按资源 ID 操作前是否校验当前用户权限 | `../prevent-web-security-bugs/references/prevent-unauthorized-access.md` |
| SSRF | 服务端 HTTP 请求目标是否来自用户输入且未过滤内网地址 | `../prevent-web-security-bugs/references/prevent-ssrf.md` |
| 路径遍历 | 文件路径是否由用户输入拼接且未规范化 | `../prevent-web-security-bugs/references/prevent-path-traversal.md` |
| OS 命令执行 | 系统命令中是否包含未转义的用户输入 | `../prevent-web-security-bugs/references/prevent-os-command-execution.md` |
| 代码执行 | 是否动态执行了来自用户输入的脚本或表达式 | `../prevent-web-security-bugs/references/prevent-code-execution.md` |
| 模板注入 | 模板引擎是否渲染了用户可控内容 | `../prevent-web-security-bugs/references/prevent-template-injection.md` |
| 反序列化 | 反序列化的数据是否来自不可信来源 | `../prevent-web-security-bugs/references/prevent-deserialization.md` |
| 凭据硬编码 | 是否有密码、密钥、Token 直接写入代码 | `../prevent-web-security-bugs/references/prevent-hardcoded-credentials.md` |
| XXE | XML 解析器是否禁用了外部实体 | `../prevent-web-security-bugs/references/prevent-xxe.md` |

#### 2B：C/C++ 代码安全检查

适用场景：变更涉及 C/C++ 内存操作、字符串处理、文件读写、系统调用、多线程。

| 风险类型 | 检查要点 | 参考文档 |
|---|---|---|
| 缓冲区溢出 | 缓冲区读写是否有长度约束 | `../prevent-c-cpp-security-bugs/references/prevent-buffer-overflow.md` |
| UAF | free/delete 后指针是否置空，后续是否继续使用 | `../prevent-c-cpp-security-bugs/references/prevent-use-after-free.md` |
| Double free | 同一块内存是否可能被释放两次 | `../prevent-c-cpp-security-bugs/references/prevent-double-free.md` |
| 格式化字符串漏洞 | 格式化函数参数是否来自不可信输入 | `../prevent-c-cpp-security-bugs/references/prevent-format-string-vuln.md` |
| 整数溢出/下溢 | 内存分配、数组索引计算是否可能溢出 | `../prevent-c-cpp-security-bugs/references/prevent-integer-overflow-underflow.md` |
| 符号扩展/类型转换 | 有符号数和无符号数混合运算是否安全 | `../prevent-c-cpp-security-bugs/references/prevent-signedness-bugs.md` |
| 条件竞争 | 多线程对共享资源的访问是否正确同步 | `../prevent-c-cpp-security-bugs/references/prevent-race-condition.md` |
| 危险函数调用 | 是否使用了 gets/strcpy/sprintf 等危险函数 | `../prevent-c-cpp-security-bugs/references/prevent-potential-dangerous-function.md` |
| QL 注入 | 是否拼接了数据库查询语句 | `../prevent-c-cpp-security-bugs/references/prevent-ql-injection.md` |
| 路径遍历 | 文件路径是否由用户输入拼接 | `../prevent-c-cpp-security-bugs/references/prevent-path-tranversal.md` |
| OS 命令执行 | system/popen/execve 是否包含用户输入 | `../prevent-c-cpp-security-bugs/references/prevent-os-command-execution.md` |

#### 2C：JavaScript/TypeScript 代码安全检查

适用场景：变更涉及 JavaScript/TypeScript 代码，包括 Node.js 后端、前端页面、构建脚本等。

| 风险类型 | 检查要点 | 参考文档 |
|---|---|---|
| Query Language 注入 | 是否拼接 SQL/NoSQL 查询语句 | `../prevent-js-security-bugs/references/prevent-ql-injection.md` |
| OS 命令注入 | child_process.exec 等是否包含用户输入 | `../prevent-js-security-bugs/references/prevent-os-command-execution.md` |
| 代码注入 | 是否使用 eval/new Function/动态 require 执行非字面量字符串 | `../prevent-js-security-bugs/references/prevent-code-injection.md` |
| 原型链污染 | 递归合并或深拷贝时键名是否来自用户输入 | `../prevent-js-security-bugs/references/prevent-prototype-pollution.md` |
| XSS | 用户输入是否未转义直接插入 DOM 或 HTML 模板 | `../prevent-js-security-bugs/references/prevent-xss.md` |
| 路径遍历 | 文件路径是否由用户输入拼接且未规范化 | `../prevent-js-security-bugs/references/prevent-path-traversal.md` |
| SSRF | 服务端 HTTP 请求目标是否由用户输入控制 | `../prevent-js-security-bugs/references/prevent-ssrf.md` |
| 不安全反序列化 | 是否反序列化来自不可信来源的数据 | `../prevent-js-security-bugs/references/prevent-deserialization.md` |
| 弱随机数 | 是否使用 Math.random() 生成安全敏感值 | `../prevent-js-security-bugs/references/prevent-weak-random.md` |
| PostMessage Origin 校验缺失 | 接收跨窗口消息时是否校验 event.origin | `../prevent-js-security-bugs/references/prevent-postmessage-origin.md` |
| 时序攻击 | 是否使用 === 比较 HMAC/Token 等安全敏感字符串 | `../prevent-js-security-bugs/references/prevent-timing-attack.md` |
| ReDoS | 是否存在嵌套量词或用户输入构造的动态正则 | `../prevent-js-security-bugs/references/prevent-redos.md` |
| Buffer 安全问题 | 是否使用已废弃的 new Buffer 或 allocUnsafe 未填充 | `../prevent-js-security-bugs/references/prevent-buffer-issues.md` |
| 不安全传输 | 是否通过 HTTP 加载外部资源或请求 API | `../prevent-js-security-bugs/references/prevent-insecure-transport.md` |
| 硬编码凭证 | 是否将 API Key/密码/密钥直接写入源代码 | `../prevent-js-security-bugs/references/prevent-hardcoded-secrets.md` |

#### 2D：IaC 基础设施配置安全检查

适用场景：变更涉及 Kubernetes YAML、Dockerfile、docker-compose、Helm chart、Terraform 等基础设施配置文件。

| 风险类型 | 检查要点 | 参考文档 |
|---|---|---|
| 特权容器与 root 运行 | 容器是否以特权模式或 root 用户运行 | `../prevent-iac-security-bugs/references/prevent-privileged-containers.md` |
| 凭据硬编码 | env/ConfigMap/Dockerfile 中是否含明文密码或密钥 | `../prevent-iac-security-bugs/references/prevent-hardcoded-secrets.md` |
| 网络暴露与策略缺失 | Service 类型是否合理，是否配置 NetworkPolicy | `../prevent-iac-security-bugs/references/prevent-network-exposure.md` |
| Dockerfile 安全 | 是否存在 ADD 替代 COPY、未指定 USER、缺少 HEALTHCHECK 等问题 | `../prevent-iac-security-bugs/references/prevent-dockerfile-security.md` |
| RBAC 过度授权 | Role/ClusterRole 是否使用通配符或过度授权 | `../prevent-iac-security-bugs/references/prevent-rbac-misconfiguration.md` |
| 宿主机路径挂载 | 是否挂载 hostPath 或 Docker socket 导致逃逸风险 | `../prevent-iac-security-bugs/references/prevent-host-path-mount.md` |
| Capabilities 滥用 | 是否授予了不必要的 Linux Capabilities | `../prevent-iac-security-bugs/references/prevent-capabilities-misconfiguration.md` |

---

### 第三步：输出审查结论

完成所有适用的安全检查后，按以下格式输出结论：

#### 情况一：发现安全漏洞

```
## 安全审查结果：发现 {N} 个安全问题

| # | 文件 | 行号 | 漏洞类型 | 风险等级 | 问题描述 |
|---|---|---|---|---|---|
| 1 | path/to/file.java | L42 | SQL 注入 | 高危 | 直接拼接用户输入构造 SQL 查询 |
| 2 | path/to/file.java | L78 | 越权访问 | 高危 | 未校验当前用户是否有权限访问该资源 |

正在修复上述问题...
```

随后立即进入第四步执行修复。

#### 情况二：未发现安全漏洞

```
## 安全审查结果：未发现安全漏洞

已检查以下风险类型：{列出实际检查的风险类型}
本次修改的代码符合安全编码规范，审查完成。
```

审查结束，无需执行第四步。

---

### 第四步：修复安全漏洞（仅在发现漏洞时执行）

对第三步列出的每个漏洞，按以下原则修复：

- **精准修复**：仅修改存在漏洞的代码，不扩大改动范围
- **参照规范**：依据第二步读取的参考文档中的安全 API 和防御模式进行修复
- **保持功能**：修复后代码逻辑与原始需求保持一致，不引入功能回归
- **修复验证**：修复完成后，针对同一风险类型重新检查，确认漏洞已消除

修复完成后，输出修复摘要：

```
## 修复摘要

| # | 漏洞类型 | 修复方式 | 状态 |
|---|---|---|---|
| 1 | SQL 注入 | 改用参数化查询（PreparedStatement） | 已修复 |
| 2 | 越权访问 | 在查询前增加 userId 归属校验 | 已修复 |

所有安全问题已修复，审查完成。
```

---

## 审查原则

- **完整覆盖**：本次变更涉及多少文件，就审查多少文件，不遗漏
- **按需查阅**：每个识别出的风险类型，必须先读取对应参考文档再判断，避免误判
- **零容忍高危**：高危/严重风险必须修复，不可以注释或文档说明代替修复
- **最小化改动**：修复只改有问题的代码，不借机重构无关逻辑
