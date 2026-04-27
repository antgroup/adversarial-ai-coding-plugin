# 防范格式化字符串漏洞安全编码规范

## 什么是格式化字符串漏洞

格式化字符串漏洞（Format String Vulnerability）是指程序将**不受信任的外部输入**直接作为格式化函数（如 `printf`、`sprintf`、`fprintf`、`syslog` 等）的**格式化字符串参数**，而非数据参数传入，从而导致攻击者可以控制程序行为的安全漏洞。

攻击者可以通过在输入中嵌入 `%x`、`%s`、`%n` 等格式化说明符来：
- 任意读取进程栈内存或堆内存（信息泄露）
- 通过 `%n` 向任意内存地址写入数据（任意写，可导致 RCE）
- 造成程序崩溃（DoS）

**危险等级：严重（Critical）**，可导致远程代码执行（RCE）或敏感信息泄露。

---

**典型攻击场景1：栈内存信息泄露**

服务端将用户输入的用户名直接拼入日志并用 `printf` 打印。攻击者将用户名设置为 `%x.%x.%x.%x`，程序将栈上的数据（可能包含堆地址、栈地址、canary值、函数返回地址等）以十六进制格式打印出来，帮助攻击者绕过 ASLR 进行后续攻击。

**典型攻击场景2：利用 `%n` 实现任意地址写**

攻击者构造包含 `%n` 的输入字符串。`%n` 会将当前已输出的字节数写入到对应参数所指向的内存地址。通过精心布局格式化字符串，攻击者可以将任意值写入任意内存地址（如函数指针、GOT 表项），最终劫持程序控制流，实现远程代码执行。

---

## 漏洞示例（禁止）

### 示例1：直接将用户输入作为格式化字符串（危险）
```c
#include <stdio.h>

// ❌ 危险：user_input 直接作为格式字符串，攻击者输入 "%x%x%x" 即可泄露栈内存
void log_username(const char *user_input) {
    printf(user_input);           // 严重错误！
    fprintf(stderr, user_input);  // 同样危险！
}
```

### 示例2：用 sprintf 拼接后再格式化（危险）
```c
#include <stdio.h>

// ❌ 危险：即使经过拼接，最终作为格式字符串的字符串仍含有用户输入
void notify(const char *event_type, const char *user_msg) {
    char buf[256];
    // 看起来做了拼接，实际上 buf 的内容仍由用户控制
    snprintf(buf, sizeof(buf), "[%s] ", event_type);
    strncat(buf, user_msg, sizeof(buf) - strlen(buf) - 1);
    printf(buf); // ❌ 仍然危险！buf 中含有用户输入的格式符
}
```

### 示例3：syslog 中的格式化字符串漏洞（危险）
```c
#include <syslog.h>

// ❌ 危险：syslog 同样是格式化函数族，直接传入用户输入会导致漏洞
void log_error(const char *user_message) {
    syslog(LOG_ERR, user_message); // 严重错误！
}
```

---

## 安全编码示例（推荐）

### 示例1：始终使用固定的格式化字符串字面量
```c
#include <stdio.h>

// ✅ 安全：格式字符串为编译期常量字面量，用户输入仅作为数据参数 %s 传入
void log_username(const char *user_input) {
    printf("%s", user_input);           // 正确：user_input 是数据，不是格式串
    fprintf(stderr, "%s\n", user_input); // 正确
}
```

### 示例2：syslog 使用固定格式字符串
```c
#include <syslog.h>

// ✅ 安全：格式字符串固定，用户数据作为 %s 参数传入
void log_error(const char *user_message) {
    syslog(LOG_ERR, "%s", user_message); // 正确
}
```

## 核心规则总结

| 规则 | 说明 |
|---|---|
| **格式串必须是字面量** | `printf`/`fprintf`/`sprintf`/`syslog` 等函数的格式参数必须为编译期字符串常量 |
| **用户输入只能作数据** | 所有外部数据只能作为 `%s`/`%d` 对应的参数，绝不能成为格式串本身 |