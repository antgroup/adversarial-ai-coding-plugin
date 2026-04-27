# 防范条件竞争（Race Condition）安全编码规范

## 什么是条件竞争

条件竞争（Race Condition）是指程序的正确性依赖于多个并发执行的操作的相对顺序或时序，而当该顺序无法得到保证时，就会产生安全漏洞。在C/C++服务端开发中，条件竞争主要分为两类：

- **TOCTOU（Time-of-Check to Time-of-Use）**：程序先检查某个资源（如文件权限、文件是否存在），再使用该资源，但在"检查"和"使用"之间的时间窗口内，攻击者可以修改该资源的状态，使检查结果失效。
- **多线程共享资源竞争**：多线程并发访问共享内存、文件、数据库等资源时，缺少适当的同步机制，导致数据损坏、逻辑错误或安全绕过。

---

**典型攻击场景1：临时文件 TOCTOU**

程序使用 `tmpnam()` 生成一个临时文件名，然后再调用 `open()` 打开该文件。攻击者在 `tmpnam()` 返回文件名之后、`open()` 执行之前，在该路径创建一个指向 `/etc/passwd` 的符号链接。程序随后打开的实际上是系统敏感文件，而非预期的临时文件，导致敏感数据泄露或覆盖。

**典型攻击场景2：文件权限检查绕过**

一个 Web 服务在提供文件下载前，先调用 `access()` 检查用户是否有权限访问该文件，通过后再调用 `open()` 读取文件内容。攻击者在 `access()` 检查通过之后、`open()` 执行之前，将该文件路径替换为一个指向 `/etc/shadow` 的符号链接。由于 Web 服务以 root 权限运行，最终 `open()` 成功读取了本不应访问的影子密码文件。

---

## 漏洞示例（禁止使用）

### 示例1：使用 `tmpnam` 创建临时文件（危险）

```c
#include <stdio.h>
#include <stdlib.h>

/* ❌ 危险：tmpnam + fopen 之间存在 TOCTOU 竞争窗口 */
int write_temp_data(const char *data, size_t len) {
    char filename[L_tmpnam];

    /* tmpnam 生成文件名后返回，此时文件尚未创建 */
    /* 攻击者可在此窗口期创建同名符号链接 */
    if (tmpnam(filename) == NULL) {
        return -1;
    }

    /* 攻击者已将 filename 替换为指向敏感文件的符号链接 */
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fwrite(data, 1, len, fp);
    fclose(fp);
    return 0;
}
```

**问题分析：** `tmpnam()` 只生成文件名，不创建文件，也不持有任何锁。从函数返回到 `fopen()` 调用之间存在时间窗口，攻击者可在此期间创建同名符号链接，导致程序写入攻击者指定的任意文件（CWE-377）。

---

### 示例2：先检查权限再使用文件（危险）

```c
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* ❌ 危险：access() + open() 之间存在 TOCTOU 竞争窗口 */
int read_user_file(const char *filepath, char *buf, size_t buf_size) {
    /* 先检查：当前用户是否有读权限 */
    if (access(filepath, R_OK) != 0) {
        fprintf(stderr, "Access denied: %s\n", filepath);
        return -1;
    }

    /* 攻击者可在此处将 filepath 替换为符号链接 */
    /* 后使用：此时实际打开的文件已被攻击者替换 */
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, buf, buf_size - 1);
    if (n < 0) {
        close(fd);
        return -1;
    }
    buf[n] = '\0';
    close(fd);
    return (int)n;
}
```

**问题分析：** `access()` 检查的是调用进程的**真实用户ID**对文件的权限，而 `open()` 使用的是**有效用户ID**。当进程以 setuid root 运行时，`access()` 可能拒绝，而 `open()` 却可以成功。此外，两次调用之间存在竞争窗口，攻击者可用符号链接替换目标路径（CWE-367）。


### 示例3：无原子化访问引用计数 (禁止)
```C
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int ref_count;  /* 无保护的引用计数 */
    char *data;
} Object;

/* 增加引用 */
void obj_retain(Object *obj) {
    obj->ref_count++;          /* ❌ 非原子：读-改-写三步，线程可在任意步骤间被切换 */
}

/* 释放引用，归零时销毁 */
void obj_release(Object *obj) {
    obj->ref_count--;          /* ❌ 同上 */
    if (obj->ref_count == 0) { /* ❌ 减法与判断之间也存在窗口 */
        free(obj->data);
        free(obj);
    }
}
```


---

## 安全编码示例（推荐）

### 示例1：使用 `mkstemp` 安全创建临时文件

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* ✅ 安全：mkstemp 原子地创建文件并返回文件描述符，不存在竞争窗口 */
int write_temp_data(const char *data, size_t len) {
    /* 模板末尾必须是 6 个 'X'，mkstemp 会将其替换为唯一字符串 */
    char template[] = "/tmp/myapp_XXXXXX";

    /* mkstemp 原子地完成"生成名称 + 创建文件 + 打开文件"三个步骤 */
    /* 返回的文件描述符以 O_RDWR | O_CREAT | O_EXCL 标志打开，确保独占访问 */
    int fd = mkstemp(template);
    if (fd < 0) {
        perror("mkstemp");
        return -1;
    }

    /* 立即解除文件名链接，使临时文件在关闭后自动删除（可选但推荐） */
    if (unlink(template) != 0) {
        perror("unlink");
        /* 继续执行，unlink 失败不是致命错误 */
    }

    ssize_t written = write(fd, data, len);
    close(fd);

    if (written < 0 || (size_t)written != len) {
        return -1;
    }
    return 0;
}
```

**安全要点：**
- `mkstemp()` 以原子方式生成唯一文件名并立即以 `O_EXCL` 标志创建文件，消除了 TOCTOU 窗口。
- 返回的是文件描述符而非文件名，后续操作直接通过 fd 进行，无需再次按名查找。
- 调用 `unlink()` 确保临时文件在使用完毕后自动清理。

> **平台说明**：`mkstemp()` 是 POSIX 专属函数，Windows 上不可用。

**跨平台替代方案：使用 C 标准的 `tmpfile()`**

`tmpfile()` 是 C89 标准函数，在所有平台（Linux/macOS/Windows）上均可使用，同样以原子方式创建临时文件，关闭后自动删除，不存在 TOCTOU 窗口。局限：无法指定目录，返回 `FILE*` 而非 fd。

```c
#include <stdio.h>

/* ✅ 跨平台安全：C 标准 tmpfile() 原子创建临时文件，关闭后自动删除 */
int write_temp_data_portable(const char *data, size_t len) {
    FILE *fp = tmpfile();   /* 原子创建，不存在 TOCTOU 窗口 */
    if (fp == NULL) {
        perror("tmpfile");
        return -1;
    }

    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);   /* 自动删除临时文件 */

    return (written == len) ? 0 : -1;
}
```

**Windows 专属替代方案：使用 `GetTempFileNameW` + `CreateFileW`**

若需在 Windows 上指定目录或获取文件句柄，使用 Win32 API。需注意 `GetTempFileNameW` 返回到 `CreateFileW` 调用之间存在极短的竞争窗口，攻击者可在此窗口内将临时文件替换为：
- **符号链接**：指向 `/etc/shadow` 等敏感文件，`CreateFileW` 若跟随符号链接将覆盖目标。
- **硬链接**：硬链接是普通文件（无重解析点标记），但与敏感文件共享同一 inode；写入后实际修改的是敏感文件本身。

正确防御需同时应对两种攻击：
- `FILE_FLAG_OPEN_REPARSE_POINT`：打开符号链接本身而不跟随，再通过 `FILE_ATTRIBUTE_REPARSE_POINT` 检测并拒绝。
- `nNumberOfLinks == 1`：硬链接创建后目标文件的链接计数必然 ≥2，可以此识别并拒绝硬链接。

```c
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

/* ✅ Windows 安全：原子创建 + 符号链接检测 + 硬链接检测 */
int write_temp_data_windows(const char *data, size_t len) {
    wchar_t temp_dir[MAX_PATH];
    wchar_t temp_file[MAX_PATH];

    if (GetTempPathW(MAX_PATH, temp_dir) == 0) return -1;

    /*
     * GetTempFileNameW(uUnique=0) 同时生成唯一名称并原子创建空文件，
     * 函数返回后该路径处已存在一个真实文件。
     */
    if (GetTempFileNameW(temp_dir, L"app", 0, temp_file) == 0) return -1;

    /*
     * OPEN_EXISTING：只打开 GetTempFileNameW 刚创建的那个文件，不重建。
     * FILE_FLAG_OPEN_REPARSE_POINT：打开符号链接本身而非跟随它。
     * 若攻击者将临时文件替换为硬链接或符号链接，下方的属性检查会将其拒绝。
     */
    HANDLE hFile = CreateFileW(
        temp_file,
        GENERIC_WRITE,
        0,                    /* 独占访问，不共享 */
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE |
        FILE_FLAG_OPEN_REPARSE_POINT,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(hFile, &info)) {
        CloseHandle(hFile);
        return -1;
    }
    /* 拒绝符号链接（重解析点） */
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        CloseHandle(hFile);
        return -1;
    }
    /*
     * 拒绝硬链接：硬链接使目标文件的 nNumberOfLinks >= 2。
     * 合法的临时文件此时应只有一个链接（刚由 GetTempFileNameW 创建）。
     */
    if (info.nNumberOfLinks != 1) {
        CloseHandle(hFile);
        return -1;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data, (DWORD)len, &written, NULL);
    CloseHandle(hFile);   /* FILE_FLAG_DELETE_ON_CLOSE 确保关闭后自动删除 */

    return (ok && written == (DWORD)len) ? 0 : -1;
}
#endif /* _WIN32 */
```

---

### 示例2：使用 `O_NOFOLLOW` 和 `openat` 安全打开文件

```c
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>   /* strchr */

/* ✅ 安全：直接以受限标志打开文件，由内核保证原子性，避免 TOCTOU */
int read_user_file(int dir_fd, const char *filename, char *buf, size_t buf_size) {
    if (filename == NULL || buf == NULL || buf_size == 0) {
        return -1;
    }

	if (strchr(filename, '/') != NULL) {   /* 绝对路径 / 目录遍历 */
        fprintf(stderr, "    [FIXED] 拒绝含 '/' 的 filename: %s\n", filename);
        return -1;
    }

    /*
     * 使用 openat + O_NOFOLLOW 组合：
     *   - O_NOFOLLOW：若路径最终组件是符号链接则直接失败，防止符号链接攻击
     *   - O_RDONLY：只读方式打开
     *   - dir_fd：在指定目录下查找文件，防止目录遍历
     * 整个"权限检查 + 文件打开"由内核原子完成，不存在竞争窗口。
     */
    int fd = openat(dir_fd, filename, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP || errno == ENOENT) {
            fprintf(stderr, "Symlink or missing file rejected: %s\n", filename);
        } else {
            perror("openat");
        }
        return -1;
    }

    /* 额外验证：确认打开的确实是普通文件，而非设备文件等特殊类型 */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Not a regular file\n");
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);

    if (n < 0) {
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}
```

**安全要点：**
- 彻底消除了 `access()` + `open()` 模式：不进行预检查，直接由内核在 `openat()` 调用内部完成权限验证和文件打开，保证原子性。
- `O_NOFOLLOW` 标志让内核在目标路径是符号链接时直接返回 `ELOOP` 错误，从根本上阻断符号链接攻击。
- `fstat()` + `S_ISREG` 校验确保打开的是普通文件，防止打开 `/dev/mem` 等特殊文件。
- 使用 `openat(dir_fd, ...)` 将文件查找限定在受信任的目录下，配合 `O_NOFOLLOW` 防止目录遍历与符号链接组合攻击。

### 示例3：引用计数定义为原子类型
```C
#include <stdatomic.h>
#include <stdlib.h>

typedef struct {
    atomic_int ref_count;  /* ✅ 原子类型，所有操作不可分割 */
    char *data;
} Object;

void obj_retain(Object *obj) {
    atomic_fetch_add(&obj->ref_count, 1);  /* ✅ 原子加，无竞争 */
}

void obj_release(Object *obj) {
    /* fetch_sub 返回旧值，若旧值为 1 说明当前是最后一个引用 */
    if (atomic_fetch_sub(&obj->ref_count, 1) == 1) {  /* ✅ 减法与判断一步完成 */
        free(obj->data);
        free(obj);
    }
}
```

---

**总结原则：**

| 危险用法 | 安全替代 |
|---|---|
| `tmpnam()` + `fopen()` | `mkstemp()` |
| `tempnam()` + `open()` | `mkstemp()` / `mkostemp()` |
| `access()` + `open()` | 直接 `open()` 检查返回值和 `errno` |
| `open()` 不带 `O_NOFOLLOW` | `open()` / `openat()` + `O_NOFOLLOW` |
| `stat()` + `open()` | `open()` + `fstat()` |
| int ref_count | atomic_int ref_count |