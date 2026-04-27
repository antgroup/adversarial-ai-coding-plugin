# 防范 CWE-676 使用具有潜在危险函数的安全编码规范

---

## 什么是 CWE-676

CWE-676（Use of Potentially Dangerous Function）指程序调用了在设计上存在内在缺陷的标准库函数——这些函数虽然合法存在于 C 标准库中，但由于其接口设计缺少安全保护（无边界检查、依赖全局静态状态、错误处理缺失等），在稍有不慎的使用中极易引发缓冲区溢出、竞态条件、数据损坏或程序行为未定义等严重后果。

CWE-676 与 CWE-120（缓冲区拷贝不检查大小）的区别在于：**危险不一定来自缓冲区大小本身，而来自函数设计的结构性缺陷**，例如隐式共享状态、吞噬错误、依赖调用方做不可能做到的保证等。

---

### **典型攻击场景 1：`strtok` 在多线程环境下引发数据竞争与逻辑错误**

`strtok` 使用一个**进程级全局静态指针**保存上次分割的位置。当两个线程同时解析不同字符串时，它们共享同一个隐藏状态，彼此覆盖，导致一方跳过 token、越过原字符串末尾继续访问，最终产生乱序输出、读取悬空指针或访问越界内存。

更隐蔽的是：即使在单线程中，**任何嵌套调用**（例如在解析外层字段的过程中调用了某个内部也使用 `strtok` 的辅助函数）都会导致外层解析状态被完全破坏，而这种错误极难通过代码审查发现。

```
线程 A：strtok("apple,banana", ",")  → 保存内部指针 → P1
线程 B：strtok("foo:bar", ":")       → 覆盖内部指针 → P2
线程 A：strtok(NULL, ",")            → 使用 P2，读取线程 B 的字符串！
                                        ↑ 数据竞争 + 越界访问
```

## 漏洞示例（禁止使用）

### 示例 1（危险）：多线程环境中使用 `strtok` 解析并发请求

```c
#include <stdio.h>
#include <string.h>
#include <pthread.h>

// ❌ 危险：strtok 使用全局静态指针，多线程并发调用时互相破坏彼此的解析状态
// 结果：token 乱序、读取悬空指针、偶发崩溃，且极难复现（数据竞争）
void *parse_request(void *arg) {
    char *request = (char *)arg;  // e.g. "GET /index.html HTTP/1.1"

    char *method = strtok(request, " ");   // 第一次调用，设置全局内部指针
    char *path   = strtok(NULL, " ");      // 依赖全局内部指针 ← 线程不安全
    char *proto  = strtok(NULL, "\r\n");   // 同上

    printf("Method: %s, Path: %s, Proto: %s\n", method, path, proto);
    return NULL;
}

// 两个线程同时调用 parse_request，内部指针被交替覆盖
```

**风险点**：① 全局静态指针在线程间共享；② 没有任何互斥保护；③ 原始字符串被 `\0` 原位修改，无法重入。

### 示例2（危险）：localtime/gmtime 返回指向内部静态buffer的指针
```C
#include <stdio.h>
#include <time.h>

int main(void) {
    time_t t1 = 1000000000;
    time_t t2 = 1700000000;

    // ❌ 危险：localtime 每次返回同一个静态 struct tm 的指针
    struct tm *tm1 = localtime(&t1);  // tm1 → 静态 struct tm，填入 t1 的值
    struct tm *tm2 = localtime(&t2);  // tm2 → 同一个静态 struct tm，覆盖为 t2 的值
                                      // tm1 现在也是 t2 的内容！

    // 两者指向同一地址
    printf("same pointer: %s\n", (tm1 == tm2) ? "yes" : "no");  // yes

    // tm1->tm_year 实际上是 t2 的年份（2023），而非 t1 的年份（2001）
    printf("t1 year = %d\n", 1900 + tm1->tm_year);  // 输出 2023，不是 2001！
    printf("t2 year = %d\n", 1900 + tm2->tm_year);  // 输出 2023
    return 0;
}
```

## 安全编码示例（推荐）

### 示例 1：用 `strtok_r`（POSIX）/ `strtok_s`（C11）替代 `strtok`

```c
#include <stdio.h>
#include <string.h>
#include <pthread.h>

// ✅ 安全：strtok_r 将内部状态保存在调用方提供的 saveptr 中
// 每个线程持有自己的 saveptr，互不干扰，支持嵌套调用
void *parse_request(void *arg) {
    // 必须操作副本：strtok_r 同样会原位插入 '\0'
    char request_copy[256];
    strncpy(request_copy, (char *)arg, sizeof(request_copy) - 1);
    request_copy[sizeof(request_copy) - 1] = '\0';

    char *saveptr = NULL;  // 每个线程/调用栈各自独立的状态指针

    char *method = strtok_r(request_copy, " ", &saveptr);
    char *path   = strtok_r(NULL,         " ", &saveptr);
    char *proto  = strtok_r(NULL,        "\r\n", &saveptr);

    // 防御性空指针检查：输入格式不符时任一 token 可能为 NULL
    if (!method || !path || !proto) {
        fprintf(stderr, "Invalid request format\n");
        return NULL;
    }

    printf("Method: %s, Path: %s, Proto: %s\n", method, path, proto);
    return NULL;
}

// Windows 平台等价替代：
// char *token = strtok_s(str, delim, &context);  // C11 Annex K
```

### 示例2：用 localtime_r/gemtime_r/localtime_s，调用方提供`struct tm`
POSIX 下的写法
```C
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>

// ✅ 正确比较本地时间与 UTC 时间
void print_both_safe(time_t t) {
    struct tm local_tm, utc_tm;  // 各自独立分配在栈上

    // localtime_r / gmtime_r 写入调用方提供的 struct tm，互不干扰
    if (localtime_r(&t, &local_tm) == NULL ||
        gmtime_r(&t,   &utc_tm)   == NULL) {
        perror("time conversion failed");
        return;
    }


}
```

Windows 下的等价写法:
```C
// C11 Annex K（MSVC 支持，glibc 默认不开启）
struct tm tm_val;
localtime_s(&tm_val, &t);   // 注意参数顺序与 localtime_r 相反！
```
**要点**：① `saveptr` 存储在调用方的栈帧上，线程天然隔离；② 操作字符串副本，保留原始数据；③ 每个 token 结果均需空指针检查。




### 核心原则总结
| 危险函数 | 安全函数(POSIX) | 安全函数(Windows) | 
| strtok | strtok_r | strtok_s | 
| ctime(&t) | ctime_r(&t, buf) | ctime_s(buf, bufsize, &t) |
| localtime(&t) | localtime_r(&t, &tm) | localtime_s(&tm, &t) |
