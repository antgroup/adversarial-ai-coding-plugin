# 防范路径遍历安全编码规范

## 什么是路径遍历

路径遍历（Path Traversal，也称目录遍历）是指攻击者通过在文件路径中注入 `../`、`..\`、`%2e%2e%2f` 等特殊序列，使程序跳出预期的根目录，从而访问、读取或写入系统中任意位置的文件（如 `/etc/passwd`、`/etc/shadow`、敏感配置文件等）。在 C/C++ 程序中，凡是将用户可控字符串直接或间接拼接成文件路径后传入 `fopen`、`open`、`stat`、`unlink` 等系统调用的代码，均可能存在此风险。

**典型攻击场景1：Web 文件下载接口**

某 C++ HTTP 服务允许客户端通过 `GET /download?file=report.pdf` 下载文件。服务端将请求参数直接拼接到 Web 根目录：

```
/var/www/files/ + "../../etc/passwd"  →  /etc/passwd
```

攻击者构造请求 `GET /download?file=../../etc/passwd`，即可读取系统账户文件。

**典型攻击场景2：固件升级包解压**

嵌入式设备接收用户上传的 tar/zip 固件包并解压到指定目录。若解压时不校验包内文件名，攻击者可在压缩包中放入路径为 `../../../../etc/cron.d/backdoor` 的文件（"Zip Slip"攻击），解压后在系统定时任务目录植入后门。

---

## 漏洞示例（禁止使用）

### 示例1（危险）：直接拼接用户输入路径后调用 fopen

```c
/* 危险：将用户提供的 filename 直接拼接到 base_dir 后打开文件 */
#include <stdio.h>
#include <string.h>

#define BASE_DIR "/var/www/files/"

int serve_file(const char *filename) {
    char filepath[512];

    /* ❌ 未对 filename 做任何过滤，攻击者可传入 "../../etc/passwd" */
    snprintf(filepath, sizeof(filepath), "%s%s", BASE_DIR, filename);

    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        return -1;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        fwrite(buf, 1, n, stdout);
    }
    fclose(fp);
    return 0;
}
```

**风险说明**：`filename` 完全由外部控制，攻击者输入 `../../etc/shadow` 即可绕过 `BASE_DIR` 限制读取敏感文件。`snprintf` 在此只防止了缓冲区溢出，但没有阻止路径穿越。

---

### 示例2（危险）：仅过滤字面量 `../` 但未规范化路径

```c
/* 危险：简单字符串匹配不足以防御路径遍历 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BASE_DIR "/srv/uploads/"

int open_user_file(const char *user_input) {
    char path[1024];

    /* ❌ 仅检查字面量 "../"，无法防御编码变体或多重穿越 */
    if (strstr(user_input, "../") != NULL) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s%s", BASE_DIR, user_input);

    /* 攻击者可用 "..%2f"、"....///"、"%2e%2e%2f" 等绕过上面的检查 */
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    fclose(fp);
    return 0;
}
```

**风险说明**：仅匹配 `../` 字符串无法对抗 URL 编码（`%2e%2e%2f`）、双斜线（`..//`）、大小写变体（Windows 下 `..\`）等绕过手段。正确做法是先将路径规范化，再做前缀校验。

---

## 安全编码示例（推荐）

### 示例1：使用 realpath 规范化后校验路径前缀（C99）

```c
/* 推荐：先用 realpath 解析绝对路径，再校验是否以允许的根目录为前缀 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>   /* PATH_MAX */

#define BASE_DIR "/var/www/files"   /* 不以 '/' 结尾，方便后续 strncmp */

/*
 * 安全地在 BASE_DIR 范围内打开文件。
 * 返回值：成功返回 FILE*，失败返回 NULL。
 */
FILE *safe_open_file(const char *filename) {
    if (filename == NULL || filename[0] == '\0') {
        return NULL;
    }

    /* 1. 拼接候选路径（未规范化） */
    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s/%s", BASE_DIR, filename);
    if (n < 0 || (size_t)n >= sizeof(candidate)) {
        /* 路径过长 */
        return NULL;
    }

    /* 2. 用 realpath 解析所有 '..', 符号链接, 多余斜线等，得到规范绝对路径 */
    char resolved[PATH_MAX];
    if (realpath(candidate, resolved) == NULL) {
        /*
         * realpath 在文件不存在时也会失败（ENOENT）。
         * 若业务需要支持"尚未存在的文件"，可先对父目录调用 realpath，
         * 再手动附加文件名并做前缀检查。
         */
        return NULL;
    }

    /* 3. 校验规范路径是否以 BASE_DIR 为前缀，防止穿越 */
    size_t base_len = strlen(BASE_DIR);
    if (strncmp(resolved, BASE_DIR, base_len) != 0) {
        /* 路径穿越，拒绝访问 */
        return NULL;
    }
    /*
     * 额外检查：BASE_DIR 后的下一个字符必须是 '/' 或 '\0'，
     * 防止 BASE_DIR="/srv/data" 被 "/srv/data_evil" 误匹配。
     */
    if (resolved[base_len] != '/' && resolved[base_len] != '\0') {
        return NULL;
    }

    /* 4. 路径合法，打开文件 */
    return fopen(resolved, "r");
}
```

**要点说明**：

- `realpath` 会解析所有 `..`、符号链接和冗余斜线，返回真实的绝对路径，从根本上消除路径穿越的可能性。
- 前缀校验必须同时检查分隔符，避免路径前缀被"相邻目录名"绕过。
- 对不存在的目标文件，可先对其父目录调用 `realpath`，再附加经白名单校验的文件名（见示例2）。

### 示例2: 规范化路径后校验路径前缀（C++17）

C++17 的`<filesystem>`提供了跨平台的路径规范化能力，是现代C++的首选方案
```C
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

static const fs::path BASE_DIR = "/var/www/files";

/**
 * 校验路径是否在 base 目录下。
 * fs::path 的比较是词法的，canonical 后可直接用 string 前缀比较。
 */
static bool is_within_base(const fs::path& resolved,
                            const fs::path& base) {
    // 转为字符串后做前缀比较，同时检查分隔符边界
    std::string r = resolved.string();
    std::string b = base.string();

    if (r.size() < b.size()) return false;
    if (r.compare(0, b.size(), b) != 0) return false;
    if (r.size() > b.size() && r[b.size()] != '/') return false;
    return true;
}

/**
 * 安全地在 BASE_DIR 下打开文件（只读流）。
 *
 * @param filename  用户提供的文件名
 * @return          std::ifstream（已打开）
 * @throws std::runtime_error      路径穿越
 * @throws std::filesystem::filesystem_error  路径解析失败（文件不存在等）
 */
std::ifstream safe_open(const std::string& filename) {
    if (filename.empty()) {
        throw std::runtime_error("filename must not be empty");
    }

    // 1. 规范化基础目录（解析其自身的符号链接）
    fs::path resolved_base = fs::canonical(BASE_DIR);
    // canonical 在路径不存在时抛出 filesystem_error，无需手动检查

    // 2. 构造并规范化候选路径
    fs::path candidate = resolved_base / filename;
    fs::path resolved   = fs::canonical(candidate);  // 文件须已存在

    // 3. 前缀校验
    if (!is_within_base(resolved, resolved_base)) {
        throw std::runtime_error(
            "path traversal detected: " + filename);
    }

    // 4. 打开文件流
    std::ifstream ifs(resolved, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error(
            "cannot open file: " + resolved.string());
    }
    return ifs;   // NRVO，无拷贝开销
}
```