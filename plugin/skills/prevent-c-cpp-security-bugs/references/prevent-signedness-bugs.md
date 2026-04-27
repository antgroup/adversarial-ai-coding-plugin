# 防范符号扩展/类型转换漏洞安全编码规范

## 什么是符号扩展/类型转换漏洞

符号扩展漏洞（Signedness Bug / Type Conversion Vulnerability）发生在有符号数与无符号数之间进行混合运算或强制类型转换时，导致数值被错误解释，进而引发意料之外的行为。

最典型的场景是：将一个可能为负数的有符号整型值传给一个参数类型为 `size_t`（无符号）的函数（如 `memcpy`、`malloc` 等），负数会在隐式转换后变成一个极大的正数，通常导致堆溢出或程序崩溃。此类漏洞之所以危险，在于编译器往往不会发出警告，代码逻辑表面上也"看起来正确"。

**典型攻击场景1：负长度传入 memcpy**

攻击者向服务端发送一个携带"长度"字段的请求包。服务端以 `int` 读取该字段并做了不充分校验，随后将其传给 `memcpy`。若攻击者令该字段为 `-1`，则 `(size_t)(-1)` 将变为 `0xFFFFFFFF`（或在64位系统上更大），`memcpy` 会尝试拷贝一块极大的内存区域，直接导致堆溢出和进程崩溃，严重时可被利用实现远程代码执行（RCE）。

**典型攻击场景2：有符号索引绕过边界检查**

服务端使用有符号 `int` 类型的用户输入 `index` 来访问数组。开发者仅做了 `if (index < ARRAY_SIZE)` 的上界检查，却遗漏了对负值的检查。当攻击者传入 `-1` 时，由于 `-1 < ARRAY_SIZE` 为真，索引检查通过，但随后在执行 `buffer[index]` 时，负索引会造成向数组起始地址之前的内存区域的越界读写，可能导致敏感数据泄露或内存破坏。

---

## 漏洞示例（禁止使用）

### 示例1（危险）：有符号长度传入内存拷贝函数

```c
// ❌ 危险：用有符号 int 接收用户输入的长度，未校验负值即传给 memcpy
#include <string.h>
#include <stdint.h>

void process_packet(const char *data, int user_len, char *output, size_t output_size) {
    // 问题1：user_len 为 int，若攻击者传入负数，此处判断仍可通过
    if (user_len > (int)output_size) {
        return; // 上界检查，但没有检查 user_len < 0
    }

    // 问题2：将有符号 int 隐式转换为 size_t（无符号），
    //        若 user_len = -1，则 (size_t)(-1) = 0xFFFFFFFF...，
    //        导致 memcpy 拷贝超大内存，堆溢出。
    memcpy(output, data, user_len);
}
```

**危险点分析：** `user_len` 为 `int` 类型，传入 `memcpy` 第三个参数（`size_t`）时发生隐式有符号到无符号转换，负数变成极大正数，造成严重堆溢出。

---

### 示例2（危险）：有符号索引绕过边界检查

```c
// ❌ 危险：仅检查上界，未检查负值索引
#include <stdio.h>

#define TABLE_SIZE 256
static int lookup_table[TABLE_SIZE];

int get_table_value(int index) {
    // 问题：只做了上界检查，负值 index 可绕过此检查，
    //       index = -10 时，lookup_table[-10] 访问数组外内存
    if (index >= TABLE_SIZE) {
        return -1;
    }
    return lookup_table[index]; // 越界读
}
```

**危险点分析：** `index` 为有符号 `int`，仅检查 `index >= TABLE_SIZE` 的上界，负数索引完全绕过检查，导致数组越界读，可能泄露栈/堆上的敏感数据。

---

## 安全编码示例（推荐）

### 示例1：同时校验上界和下界，使用 `size_t` 接收长度参数

```c
// ✅ 安全：使用无符号类型接收长度，并做完整边界检查
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_LEN 65536

void process_packet_safe(const char *data, size_t user_len, char *output, size_t output_size) {
    // 1. 对上界和合理范围做检查（size_t 本身已是无符号，不存在负值）
    if (user_len == 0 || user_len > MAX_PACKET_LEN || user_len > output_size) {
        return;
    }

    // 2. 安全拷贝
    memcpy(output, data, user_len);
}

// 若外部接口必须以 int 接收，则在入口处立即转换并做完整双向校验
void process_packet_from_network(const char *data, int raw_len, char *output, size_t output_size) {
    // 1. 先检查负值（下界）
    if (raw_len <= 0) {
        return;
    }

    // 2. 转换为无符号类型后再做上界检查
    size_t user_len = (size_t)raw_len;
    if (user_len > MAX_PACKET_LEN || user_len > output_size) {
        return;
    }

    memcpy(output, data, user_len);
}
```

---

### 示例2：同时校验上下界，防止负数索引越界

```c
// ✅ 安全：同时检查下界（>= 0）和上界（< TABLE_SIZE）
#include <stdio.h>

#define TABLE_SIZE 256
static int lookup_table[TABLE_SIZE];

int get_table_value_safe(int index) {
    // 同时校验下界和上界，彻底防止负索引越界
    if (index < 0 || index >= TABLE_SIZE) {
        return -1; // 非法索引，返回错误值
    }
    return lookup_table[index];
}

// 若业务语义上 index 不应为负，直接改用无符号类型，让编译器帮助排除负值
int get_table_value_unsigned(unsigned int index) {
    if (index >= TABLE_SIZE) {
        return -1;
    }
    return lookup_table[index];
}
```

---

## 核心规则总结

| 场景 | 错误做法 | 正确做法 |
|---|---|---|
| 接收用户控制的长度/大小 | 用 `int` 接收，直接传给 `memcpy`/`malloc` | 用 `size_t` 接收；或先校验 `> 0` 再转型 |
| 数组索引 | 只检查 `index < SIZE` | 同时检查 `index >= 0 && index < SIZE` |
| 有符号与无符号比较 | 直接混合比较 | 统一类型后再比较，或使用显式强制转型 |
| 函数参数类型 | 长度参数用 `int` | 长度/大小参数优先用 `size_t` 或 `uint32_t` |

> **关键原则：** 凡是来自外部（网络、文件、用户输入）的数值，在用于内存操作（`memcpy`、`malloc`、数组索引）之前，必须同时完成**下界检查（≥ 0 或 > 0）**和**上界检查（≤ 合理最大值）**，并在类型转换时保持清晰的类型语义。