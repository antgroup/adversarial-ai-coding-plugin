# 防范系统命令注入安全编码规范

## 什么是系统命令注入

系统命令注入（Command Injection，CWE-78）是指攻击者通过向程序中注入恶意系统命令，使程序在执行外部命令时执行攻击者指定的额外命令，从而获取系统控制权、窃取数据或破坏系统。

在 C/C++ 中，当使用 `system()`、`popen()`、`exec()` 系列函数、`execlp()` 等执行外部命令时，如果命令字符串中拼接了未经充分校验的用户输入，就会产生命令注入漏洞。

**典型攻击场景1：文件名参数注入**

程序根据用户上传的文件名调用外部转换工具处理文件。攻击者将文件名构造为 `malicious.jpg; rm -rf /`，程序使用 `sprintf` 拼接后直接调用 `system()`，导致 `rm -rf /` 被执行。

**典型攻击场景2：Shell 元字符注入**

程序接收用户输入的 IP 地址并执行 `ping` 命令。攻击者输入 `127.0.0.1; cat /etc/passwd`，利用分号 `;` 将恶意命令附在合法命令后，程序执行后将泄露系统密码文件内容。

---

## 漏洞示例（禁止使用）

### 示例1（危险）：使用 `system()` 直接拼接用户输入

```c
/* ❌ 危险：将用户控制的文件名直接拼接到命令中 */
int convert_jpeg_to_pdf(const char *filename, const char *output) {
    char cmd[512];
    /* 用户可控的 filename 中若含有 "; rm -rf /"，将执行恶意命令 */
    sprintf(cmd, "convert %s %s", filename, output);
    return system(cmd);
}
```

**风险分析：** `filename` 和 `output` 均来自外部，攻击者可注入 `; cat /etc/passwd`、`$(whoami)` 等 shell 元字符，`system()` 通过 `/bin/sh -c` 执行，会解析这些特殊字符，导致任意命令执行。

### 示例2（危险）：使用 `popen()` 拼接用户提供的命令字符串

```c
/* ❌ 危险：接受完整命令字符串并交由 popen 执行 */
int run_command(const char *user_cmd) {
    char full_cmd[1024];
    /* 直接将用户输入作为命令的一部分 */
    snprintf(full_cmd, sizeof(full_cmd), "sh -c \"%s\"", user_cmd);
    FILE *fp = popen(full_cmd, "r");
    if (fp == NULL) return -1;
    pclose(fp);
    return 0;
}
```

**风险分析：** 即使使用了 `snprintf` 限制了缓冲区长度，攻击者仍可通过 `"; evil_cmd; "` 注入新命令，`popen` 同样经过 shell 解析。

---

## 安全编码示例（推荐）

### 示例1：使用 `execvp()` 以参数数组方式传递命令，绕过 shell 解析

```c
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ✅ 安全：使用 execvp 直接传递参数列表，不经过 shell 解析 */
int convert_jpeg_to_pdf_safe(const char *filename, const char *output) {
    /* 对文件名进行白名单校验，只允许字母、数字、点、连字符 */
    for (const char *p = filename; *p != '\0'; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')) {
            fprintf(stderr, "Invalid character in filename\n");
            return -1;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        /* 子进程：使用 execvp 直接传递参数，不经过 shell */
        char *args[] = { "convert", (char *)filename, (char *)output, NULL };
        execvp("convert", args);
        /* execvp 失败才会到达此处 */
        _exit(127);
    }
    /* 父进程：等待子进程结束 */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
```

**安全要点：** `execvp` 直接将参数传给目标程序，不经过 shell，因此 `;`、`|`、`$()` 等元字符不会被解析。同时对输入进行了白名单校验，双重防护。

> **平台说明**：`fork()`/`execvp()`/`waitpid()` 是 POSIX 专属，Windows 上不可用。Windows 替代方案：使用 `CreateProcessA` 代替 `ShellExecute`, `ShellExecuteEx`, `WinExec`**。Windows 的 `CreateProcessA` 与 POSIX 的 `execvp` 类似——在 `lpApplicationName` 指定可执行文件路径时，命令行不经过 `cmd.exe` 解析，`;`、`&`、`|` 等 shell 元字符不会被解析，安全性等同于 `execvp`。


### 示例2：对必须调用 `system()` 的场景进行严格参数转义和白名单校验

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ✅ 安全：对 IP 地址参数进行严格白名单校验后再拼接命令 */
int ping_host_safe(const char *ip_address) {
    /* 只允许数字和点，严格校验 IPv4 格式 */
    size_t len = strlen(ip_address);
    if (len == 0 || len > 15) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)ip_address[i]) && ip_address[i] != '.') {
            fprintf(stderr, "Invalid IP address format\n");
            return -1;
        }
    }
    /* 进一步验证：每段数值范围 0-255 */
    int a, b, c, d;
    if (sscanf(ip_address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
        a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) {
        return -1;
    }

    char cmd[64];
    /* 使用 snprintf 防止缓冲区溢出，且输入已经过严格校验 */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %d.%d.%d.%d", a, b, c, d);
    return system(cmd);
}
```

**安全要点：** 对用户输入使用字符白名单和格式验证双重校验，重新用整数拼接命令字符串而不是直接嵌入原始输入，即使攻击者构造了注入字符串也会在校验阶段被拒绝。

---

## 总结建议

优先使用 `execv`/`execvp`/`execve` 等系列函数以参数数组的形式传参，彻底避免 shell 解析。若业务逻辑必须使用 `system()` 或 `popen()`，则必须对所有用户可控参数进行严格白名单校验或专用转义处理（如 `shellescape`），切勿依赖黑名单过滤。此外，对执行外部命令的进程应尽量以最小权限运行（如使用 `setuid/setgid` 降权），降低漏洞被利用后的影响范围。