# 防范整数溢出安全编码规范

## 什么是整数溢出

整数溢出（Integer Overflow）是指对整数类型变量进行算术运算时，计算结果超出了该类型所能表示的最大范围，导致数值"回绕"（wrap around）到一个意外的小值甚至负值的现象。在 C/C++ 中，有符号整数溢出属于未定义行为（Undefined Behavior），无符号整数溢出则会按模运算（modular arithmetic）静默回绕。

整数溢出本身不直接导致代码执行，但它几乎总是作为**触发缓冲区溢出（Buffer Overflow，CWE-680）的上游漏洞**出现：当溢出后的错误数值被用作 `malloc` 分配大小、`memcpy` 拷贝长度、数组下标或循环边界时，就会引发越界写入或越界读取，进而可被攻击者利用来实现任意代码执行或拒绝服务。

---

**典型攻击场景 1：乘法溢出导致堆缓冲区下溢分配**

最经典的场景是对用户可控的元素数量与元素大小做乘法后传入 `malloc`，导致malloc返回的buffer的长度过小，在后续的循环写入操作中仍然按照用户可控的元素数量进行写入，造成严重的堆溢出

**典型攻击场景 2：加法溢出导致边界检查失效**

在内存池、网络协议解析等场景中，对偏移量或长度做加法时同样可能溢出，使得看似充足的剩余空间检查完全失效：


## 漏洞示例（禁止使用）

### 示例 1 — 乘法溢出后分配堆缓冲区（危险）

```c
/* 来自真实漏洞代码的形态 */
int *alloc_items(int count) {
    /* count = 2^30 + 1 时，count * 4 在 32 位 int 下溢出为 4 */
    int *arr = (int *)malloc(count * sizeof(int));
    for (int i = 0; i < count; i++)
        arr[i] = 0;           /* 越界写入 */
    return arr;
}
```

---

### 示例 2 — 加法溢出导致内存池越界写（危险）

```c
/**
 * ❌ 危险：将外部可控的 current_used 与 data_len 直接相加后
 * 不做溢出检测就与 pool_size 比较，绕过边界检查。
 */
int allocate_pool_memory(const char *init_data, size_t data_len,
                         char *pool_buffer, size_t pool_size) {
    if (!pool_buffer || pool_size < sizeof(size_t)) return -1;

    size_t current_used;
    memcpy(&current_used, pool_buffer, sizeof(size_t));

    size_t data_area_start = sizeof(size_t);
    char  *destination     = pool_buffer + data_area_start + current_used;

    /* ❌ 问题 1：未检测 current_used + data_len 是否溢出 */
    /* ❌ 问题 2：未验证 data_area_start + current_used + data_len <= pool_size */
    memcpy(destination, init_data, data_len);   /* 潜在越界写入 */

    size_t updated_used = current_used + data_len; /* 同样可能溢出 */
    memcpy(pool_buffer, &updated_used, sizeof(size_t));
    return 0;
}
```

---

## 安全编码示例（推荐）

### 示例 1 — 乘法前做溢出检测再分配堆缓冲区

```c
#include <stdlib.h>
#include <string.h>
#include <limits.h>   /* SIZE_MAX */

/**
 * ✅ 安全：在执行乘法之前先判断结果是否会溢出，
 *    并在分配成功后同步记录实际分配大小。
 *
 * 原则：
 *   - 对任意 a * b，若 b != 0，先检查 a <= SIZE_MAX / b
 *   - 分配失败立即返回，不继续使用空指针
 */


/* 动态扩容时同样需要检测 */
int *alloc_items_safe(size_t count) {
    /* 1. 拒绝零长度请求 */
    if (count == 0) return NULL;

    /* 2. 乘法溢出检测 */
    if (count > SIZE_MAX / sizeof(int)) return NULL;

    size_t alloc_size = count * sizeof(int);
    int *arr = (int *)malloc(alloc_size);
    if (!arr) return NULL;

    for (size_t i = 0; i < count; i++)
        arr[i] = 0;

    return arr;
}
```

---

### 示例 2 — 加法前做溢出检测再执行内存池写入

```c
#include <string.h>
#include <stddef.h>

/**
 * ✅ 安全：在对 current_used + data_len 求和之前，
 *    先检测结果是否超出 size_t 范围，
 *    再检测总使用量是否超过 pool 的可用空间。
 *
 * 原则：
 *   - 加法溢出检测：若 a + b > MAX，则 b > MAX - a
 *   - 对 offset 指针运算同样要保证目标地址落在合法范围内
 *   - 成功写入后才更新 current_used，避免状态不一致
 */
int allocate_pool_memory_safe(const char *init_data, size_t data_len,
                              char *pool_buffer, size_t pool_size) {
    /* 基本参数校验 */
    if (!pool_buffer || pool_size < sizeof(size_t)) return -1;

    if (init_data == NULL) {
        return (data_len == 0) ? 0 : -1;
    }

    /* 读取当前已使用字节数 */
    size_t current_used;
    memcpy(&current_used, pool_buffer, sizeof(size_t));

    /* 数据区起始偏移 */
    size_t data_area_start = sizeof(size_t);

    /* 计算可用空间（同样需防止减法下溢，但此处 pool_size >= sizeof(size_t)
       已在入口检查，故直接相减安全） */
    size_t available = pool_size - data_area_start;

    /* ✅ 加法溢出检测：current_used + data_len 是否超出 size_t */
    if (data_len > available - current_used ||   /* 等价于检测空间不足 */
        current_used > available) {              /* 防止 available < current_used 时下溢 */
        return -1;
    }

    /* ✅ 目标地址合法性：data_area_start + current_used 不超过 pool_size */
    char *destination = pool_buffer + data_area_start + current_used;

    /* 执行拷贝 */
    memcpy(destination, init_data, data_len);

    /* ✅ 更新 used：已通过上方检测，加法安全 */
    size_t updated_used = current_used + data_len;
    memcpy(pool_buffer, &updated_used, sizeof(size_t));

    return 0;
}
```

---

## 核心规则总结

| 场景 | 危险操作 | 安全做法 |
|------|----------|----------|
| `malloc(n * size)` | 直接相乘后传入 | 先检查 `n <= SIZE_MAX / size` |
| `malloc(a + b)` | 直接相加后传入 | 先检查 `b <= SIZE_MAX - a` |
| `realloc(ptr, n * size)` | 同 malloc 乘法 | 同上，乘前检测 |