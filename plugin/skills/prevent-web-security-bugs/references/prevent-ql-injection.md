# 防范 Query Language 注入安全编码规范

## 什么是 QL 注入

QL 注入（Query Language Injection）是指攻击者通过在用户输入中嵌入恶意查询语句片段，使其被拼接进应用程序的查询语句并被数据库执行，从而绕过认证、窃取数据、篡改数据，甚至控制数据库服务器。QL 注入涵盖 SQL 注入和 NoSQL 注入两大类。

**SQL 注入典型攻击场景**：
- 登录绕过：输入 `' OR '1'='1` 使 WHERE 条件恒为真
- 数据泄露：通过 `UNION SELECT` 拼接查询其他表的敏感数据
- 数据篡改：注入 `; DROP TABLE users; --` 删除数据表

**NoSQL 注入典型攻击场景**：
- MongoDB 操作符注入：传入 `{"$gt": ""}` 绕过密码校验
- 条件篡改：通过注入 `$where` 执行任意 JavaScript 表达式

---

## 漏洞示例（禁止使用）

### SQL 字符串拼接（危险）

```java
// ❌ 危险：直接拼接用户输入到 SQL 语句
String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

```python
# ❌ 危险：Python 中使用字符串格式化拼接 SQL
sql = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
cursor.execute(sql)
```

```java
// ❌ 危险：MyBatis 中使用 ${} 拼接用户输入
// SELECT * FROM users WHERE username = '${username}'
```

### NoSQL 操作符注入（危险）

```javascript
// ❌ 危险：直接将用户输入作为 MongoDB 查询条件
// 攻击者可传入 {"$gt": ""} 绕过密码校验
const user = await db.collection('users').findOne({
  username: req.body.username,
  password: req.body.password  // 若传入 {"$gt": ""} 则条件恒为真
});
```

```python
# ❌ 危险：直接使用用户输入构造 MongoDB 查询
query = {"username": username, "password": password}
user = db.users.find_one(query)
```

---

## 安全编码示例（推荐）

### SQL：始终使用参数化查询（Parameterized Query）

参数化查询将 SQL 结构与数据严格分离，数据库驱动会对参数进行转义处理，从根本上杜绝注入。

```java
// ✅ 安全：Java JDBC 使用 PreparedStatement
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

```python
# ✅ 安全：Python 使用参数占位符
sql = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(sql, (username, password))
```

### SQL：使用 ORM 框架的标准查询方式

ORM 框架（如 MyBatis、Hibernate、SQLAlchemy、GORM）内置了参数化机制，应使用其标准查询 API，**禁止在 ORM 中拼接原生 SQL 字符串**。

```python
# ✅ 安全：SQLAlchemy ORM 查询
user = session.query(User).filter(User.username == username).first()
```

```xml
<!-- ✅ 安全：MyBatis 使用 #{} 而非 ${} -->
<select id="findByUsername" resultType="User">
  SELECT * FROM users WHERE username = #{username}
</select>

<!-- ❌ 危险：${} 是字符串替换，存在注入风险 -->
<select id="findByUsername" resultType="User">
  SELECT * FROM users WHERE username = '${username}'
</select>
```

> **MyBatis 关键区别**：`#{}` 使用参数化绑定（安全），`${}` 是字符串直接替换（危险）。仅在需要动态表名、列名等 SQL 结构时才可使用 `${}`，且此时必须通过白名单校验该值。

### SQL：动态查询条件使用白名单校验

当排序字段、表名、列名等 SQL 结构部分需要动态传入时，无法使用参数化查询，必须使用白名单校验。

```python
# ✅ 安全：白名单限制可排序的字段
ALLOWED_SORT_COLUMNS = {"created_at", "username", "email"}

sort_by = request.get("sort_by")
if sort_by not in ALLOWED_SORT_COLUMNS:
    raise ValueError(f"不允许的排序字段: {sort_by}")

sql = f"SELECT * FROM users ORDER BY {sort_by}"
cursor.execute(sql)
```

### NoSQL：对用户输入进行类型校验，拒绝非预期类型

```javascript
// ✅ 安全：校验输入类型，确保为字符串而非对象
function login(username, password) {
  if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('非法输入类型');
  }
  return db.collection('users').findOne({ username, password });
}
```

```python
# ✅ 安全：Python 中校验输入类型
if not isinstance(username, str) or not isinstance(password, str):
    raise ValueError("非法输入类型")
query = {"username": username, "password": password}
user = db.users.find_one(query)
```

### NoSQL：使用 ODM 框架的类型安全查询

```javascript
// ✅ 安全：Mongoose ODM 使用 Schema 约束字段类型
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// Schema 会自动拒绝非字符串类型的输入
const user = await User.findOne({ username, password });
```

---
