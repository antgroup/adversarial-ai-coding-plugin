# 防范查询语言注入安全编码规范

## 什么是查询语言注入

查询语言注入（Query Language Injection）是指攻击者通过将恶意查询语句片段嵌入用户可控的输入中，使程序在执行数据库或目录查询时，执行了攻击者构造的非预期逻辑，从而实现数据窃取、数据篡改、权限绕过等目的。SQL 注入、NoSQL 注入和 LDAP 注入均属于此类漏洞。在 C/C++ 程序中，由于开发者常使用字符串拼接直接构造查询语句，该漏洞尤为普遍且危害严重。

**典型攻击场景1：SQL 注入绕过登录认证**

某 C 语言 Web 后端使用如下方式构造 SQL 查询：

```c
sprintf(query, "SELECT * FROM users WHERE name='%s' AND pass='%s'", username, password);
```

攻击者将 `username` 设为 `admin' --`，拼接后查询变为：

```sql
SELECT * FROM users WHERE name='admin' --' AND pass='...'
```

`--` 注释掉了密码校验，攻击者无需密码即可以 `admin` 身份登录。

**典型攻击场景2：SQL 注入拖库**

同样使用拼接方式的查询接口，攻击者将参数设为：

```
' UNION SELECT username, password, null FROM users --
```

拼接后的查询将额外返回全部用户的账户和密码信息，导致数据大规模泄露。

---

## 漏洞示例（禁止使用）

### 示例1（危险）：使用 `sprintf` 直接拼接 SQL 语句

```c
#include <stdio.h>
#include <mysql/mysql.h>

/* ❌ 危险：用户输入未经任何处理直接拼接到 SQL 语句中 */
int query_user(MYSQL *conn, const char *username) {
    char query[512];

    /* 攻击者可构造 username = "admin' OR '1'='1" 绕过所有条件 */
    sprintf(query,
            "SELECT id, email FROM users WHERE username = '%s'",
            username);

    if (mysql_query(conn, query)) {
        return -1;
    }
    return 0;
}
```

**问题**：`sprintf` 将用户输入直接嵌入 SQL 字符串，攻击者可通过注入单引号、注释符等特殊字符完全控制查询逻辑。

---

### 示例2（危险）：使用 `strcat` / `strncat` 拼接 LDAP 过滤器

```c
#include <string.h>
#include <ldap.h>

/* ❌ 危险：LDAP 过滤器通过字符串拼接构造，未对特殊字符转义 */
int ldap_find_user(LDAP *ld, const char *username, char *result_dn, size_t dn_size) {
    char filter[256] = "(uid=";

    /* 攻击者可将 username 设为 "*)(&" 注入 LDAP 过滤逻辑 */
    strncat(filter, username, sizeof(filter) - strlen(filter) - 2);
    strncat(filter, ")", 1);

    LDAPMessage *msg = NULL;
    int rc = ldap_search_ext_s(ld, "dc=example,dc=com",
                               LDAP_SCOPE_SUBTREE,
                               filter, NULL, 0,
                               NULL, NULL, NULL, 0, &msg);
    if (rc != LDAP_SUCCESS) {
        ldap_msgfree(msg);
        return -1;
    }

    ldap_msgfree(msg);
    return 0;
}
```

**问题**：LDAP 过滤器中的 `*`、`(`、`)`、`\` 等字符具有特殊语义。未对用户输入转义就直接拼接，攻击者可通过注入 `*)(&(objectClass=*)` 等片段绕过过滤条件，遍历整个目录。

---

## 安全编码示例（推荐）

### 示例1：使用预编译语句（Prepared Statement）防止 SQL 注入

```c
#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>

/*
 * ✅ 安全：使用 mysql_stmt_prepare 将 SQL 结构与用户数据分离。
 * 参数占位符 ? 由数据库驱动在内部安全绑定，用户输入永远不会被解释为 SQL 语法。
 */
int query_user_safe(MYSQL *conn, const char *username,
                    long *out_id, char *out_email, size_t email_size) {
    if (!conn || !username || !out_id || !out_email || email_size == 0) {
        return -1;
    }

    /* 1. 准备含占位符的 SQL 模板，结构固定，不含任何用户数据 */
    const char *sql = "SELECT id, email FROM users WHERE username = ?";
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt) return -1;

    if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    /* 2. 绑定输入参数：驱动负责安全处理特殊字符，不会拼接到 SQL 中 */
    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));

    unsigned long username_len = (unsigned long)strlen(username);
    bind_in[0].buffer_type   = MYSQL_TYPE_STRING;
    bind_in[0].buffer        = (char *)username;   /* const 安全：驱动只读取 */
    bind_in[0].buffer_length = username_len;
    bind_in[0].length        = &username_len;

    if (mysql_stmt_bind_param(stmt, bind_in) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    /* 3. 执行查询 */
    if (mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    /* 4. 绑定输出结果 */
    MYSQL_BIND bind_out[2];
    memset(bind_out, 0, sizeof(bind_out));

    long id_val = 0;
    char email_buf[256] = {0};
    unsigned long email_len = 0;

    bind_out[0].buffer_type   = MYSQL_TYPE_LONG;
    bind_out[0].buffer        = &id_val;

    bind_out[1].buffer_type   = MYSQL_TYPE_STRING;
    bind_out[1].buffer        = email_buf;
    bind_out[1].buffer_length = sizeof(email_buf) - 1;
    bind_out[1].length        = &email_len;

    if (mysql_stmt_bind_result(stmt, bind_out) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_fetch(stmt) == 0) {
        *out_id = id_val;
        /* 确保不超出调用方缓冲区 */
        size_t copy_len = (email_len < email_size - 1) ? email_len : email_size - 1;
        memcpy(out_email, email_buf, copy_len);
        out_email[copy_len] = '\0';
    }

    mysql_stmt_close(stmt);
    return 0;
}
```

**要点说明**：

- SQL 模板在编译期（`mysql_stmt_prepare`）已固定，后续只向占位符绑定数据。
- 用户输入由数据库驱动内部安全处理，无论包含任何特殊字符，均不会改变查询的语义结构。
- 若所使用的 C 库不支持预编译语句，必须使用数据库提供的转义函数（如 `mysql_real_escape_string`）对每个参数进行转义后再拼接，但此方式安全性低于预编译语句，应作为最后手段。

---

### 示例2：对 LDAP 特殊字符进行严格转义

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>

/*
 * ✅ 安全：在将用户输入嵌入 LDAP 过滤器之前，
 * 按 RFC 4515 规范对所有特殊字符进行转义，
 * 确保用户数据只被视为字面值而非过滤器语法。
 *
 * RFC 4515 中需要转义的字符：
 *   NUL (0x00), '(', ')', '*', '\'
 * 其余非 ASCII 字节也应以 \xx 形式转义以保证健壮性。
 */
static int ldap_escape_filter_value(const char *input,
                                    char *out, size_t out_size) {
    if (!input || !out || out_size == 0) return -1;

    size_t in_len  = strlen(input);
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)input[i];
        int needs_escape = (c == '\0' || c == '(' || c == ')' ||
                            c == '*'  || c == '\\' || c > 0x7F);

        if (needs_escape) {
            /* 转义格式：\xx（两位十六进制） */
            if (out_pos + 3 >= out_size) return -1;   /* 防止截断 */
            snprintf(out + out_pos, 4, "\\%02x", c);
            out_pos += 3;
        } else {
            if (out_pos + 1 >= out_size) return -1;
            out[out_pos++] = (char)c;
        }
    }
    out[out_pos] = '\0';
    return 0;
}

/*
 * ✅ 安全的 LDAP 查询：对用户输入转义后再构造过滤器
 */
int ldap_find_user_safe(LDAP *ld, const char *username) {
    if (!ld || !username) return -1;

    /* 为转义后的值预留足够空间（最坏情况每字节膨胀为 3 字节） */
    size_t escaped_size = strlen(username) * 3 + 1;
    char *escaped = malloc(escaped_size);
    if (!escaped) return -1;

    /* 对用户输入执行转义 */
    if (ldap_escape_filter_value(username, escaped, escaped_size) != 0) {
        free(escaped);
        return -1;
    }

    /* 构造过滤器：转义后的字符串不含任何可被解析为 LDAP 语法的特殊字符 */
    char filter[512];
    int written = snprintf(filter, sizeof(filter), "(uid=%s)", escaped);
    free(escaped);

    if (written < 0 || (size_t)written >= sizeof(filter)) return -1;

    LDAPMessage *msg = NULL;
    int rc = ldap_search_ext_s(ld, "dc=example,dc=com",
                               LDAP_SCOPE_SUBTREE,
                               filter, NULL, 0,
                               NULL, NULL, NULL, 0, &msg);

    int ret = (rc == LDAP_SUCCESS) ? 0 : -1;
    ldap_msgfree(msg);
    return ret;
}
```

**要点说明**：

- 转义函数覆盖了 RFC 4515 规定的全部特殊字符，并对非 ASCII 字节一并转义，避免遗漏边缘情况。
- 转义缓冲区大小按最坏情况（每字节扩展为 3 字节）预留，防止截断后产生不完整的转义序列。
- 转义完成后使用 `snprintf` 构造过滤器并检查返回值，确保结果未被截断。
- 同样的转义原则适用于 LDAP DN 构造（使用 RFC 4514 中定义的转义规则）和 NoSQL 查询（对 `$`、`.` 等操作符关键字进行参数化或白名单过滤）。