---
name: prevent-c-cpp-security-bugs
description: >
  当用户需要编写、重构或修改 C/C++ 代码时，应当使用此技能。包括但不限于：
  "写一个 C 函数"、"帮我实现一个 C++ 类"、"重构这段 C 代码"、"修复这个 C++ bug"、
  "优化这段内存操作"、"添加一个网络包解析函数"、"实现文件读取功能"、"使用 memcpy/malloc"、
  "处理用户输入"、"多线程同步"、
  "智能指针"、"管理动态内存"。
  即使用户没有明确提到"安全"或"漏洞"，只要涉及 C/C++ 代码编写或修改，都应触发此技能。
---

# C/C++ 安全代码生成规范

## 技能目标

**在代码生成阶段消除安全漏洞，而非依赖事后审查。**

代码生成是拦截安全风险成本最低的时机——一旦漏洞代码进入生产环境，修复代价急剧上升。因此，在生成代码前完成威胁识别和规范查阅，能从根本上降低安全风险。

## 工作流程

按以下三步执行安全代码生成。每一步都为后续步骤提供安全保障。

### 第一步：识别安全风险

分析用户需求，判断哪些风险类型适用于当前场景。识别出的每一个风险类型都需要处理。

| 风险类型 | 典型场景 | 参考文档 |
|---|---|---|
| 缓冲区溢出 | 对缓冲区读写时未对用户输入进行长度校验 | `references/prevent-buffer-overflow.md` |
| UAF | 指针指向的内存在 free/delete 后未置空，后续继续使用 | `references/prevent-use-after-free.md` |
| Double free | 同一块内存被释放两次，破坏堆管理器数据结构 | `references/prevent-double-free.md` |
| 格式化字符串漏洞 | 不受信任的输入直接作为格式化函数参数 | `references/prevent-format-string-vuln.md` |
| 整数溢出/下溢 | 计算结果超出整数范围，常触发缓冲区溢出 | `references/prevent-integer-overflow-underflow.md` |
| 符号扩展/类型转换 | 有符号数和无符号数混合运算出错 | `references/prevent-signedness-bugs.md` |
| 条件竞争 | 多线程/进程对共享资源访问未正确同步 | `references/prevent-race-condition.md` |
| 符号链接攻击 | TOCTOU 时间间隙中被替换文件路径 | `references/prevent-race-condition.md` |
| 危险函数调用 | 调用设计上存在缺陷的标准库函数 | `references/prevent-potential-dangerous-function.md` |
| QL 注入 | 拼接 SQL/HQL/NoSQL 查询语句 | `references/prevent-ql-injection.md` |
| 路径遍历 | 文件路径由用户输入拼接 | `references/prevent-path-traversal.md` |
| OS 命令执行 | 调用 system、popen、execve 执行系统命令 | `references/prevent-os-command-execution.md` |

### 第二步：查阅安全编码规范

对第一步中识别出的每一个风险类型，读取对应的参考文档。

参考文档详细说明了该类漏洞的根因、攻击模式和安全 API 用法，帮助理解如何在代码层面消除风险。

### 第三步：完成用户需求

在理解安全规范后，遵循以下核心原则生成代码：

- **默认安全**：优先使用参数化查询、白名单校验、安全 API 等内置防护机制
- **零信任输入**：来自 HTTP 请求、外部接口的数据一律视为不可信
- **失败安全**：权限校验或输入验证失败时默认拒绝操作
- **边界防御**：所有内存读写、字符串复制、数组遍历必须有显式长度约束
- **初始化与清理**：变量诞生时有确定值，敏感数据消亡时彻底擦除
- **算数安全**：内存分配、数组索引计算前确保不会溢出、截断或符号错误
- **编译器权限**：不需要修改的数据、指针或对象状态用 const 禁止修改
- **并发安全**：共享资源访问保证原子性或被正确同步

---

## 参考资源

### 参考文档
- **`references/prevent-buffer-overflow.md`** — 缓冲区溢出防范详解
- **`references/prevent-use-after-free.md`** — 释放后使用（UAF）防范详解
- **`references/prevent-double-free.md`** — 二次释放防范详解
- **`references/prevent-format-string-vuln.md`** — 格式化字符串漏洞防范详解
- **`references/prevent-integer-overflow-underflow.md`** — 整数溢出/下溢防范详解
- **`references/prevent-signedness-bugs.md`** — 符号扩展/类型转换漏洞防范详解
- **`references/prevent-race-condition.md`** — 条件竞争防范详解
- **`references/prevent-potential-dangerous-function.md`** — 危险函数替换指南
- **`references/prevent-ql-injection.md`** — Query Language 注入防范详解
- **`references/prevent-path-traversal.md`** — 路径遍历防范详解
- **`references/prevent-os-command-execution.md`** — OS 命令执行防范详解