# 防范 Query Language 注入安全编码规范

## 什么是 Query Language 注入

Query Language 注入是指攻击者将恶意查询语句片段混入用户输入，使应用在构造数据库查询时执行了非预期的逻辑，从而导致数据泄露、篡改或删除。

**典型攻击场景1 —— SQL 注入**

应用将用户输入直接拼接到 SQL 字符串中：
```
输入: ' OR '1'='1
构造结果: SELECT * FROM users WHERE password = '' OR '1'='1'
```
攻击者无需密码即可登录任意账号。

**典型攻击场景2 —— NoSQL 注入（MongoDB）**

MongoDB 查询条件由 JSON 对象构成，攻击者可注入操作符：
```
输入: { "password": { "$gt": "" } }
构造结果: db.users.find({ username: "admin", password: { "$gt": "" } })
```
`$gt: ""` 对任意字符串均为真，绕过密码校验。

## 漏洞示例（禁止使用）

### 示例1（危险）：字符串拼接 SQL

```typescript
// 危险：直接拼接用户输入
async function getUserById(userId: string) {
  const sql = `SELECT * FROM users WHERE id = '${userId}'`;
  return db.query(sql);
}

// 攻击：userId = "' OR '1'='1' --"
// 构造结果：SELECT * FROM users WHERE id = '' OR '1'='1' --'
```

### 示例2（危险）：动态拼接 WHERE 条件

```typescript
// 危险：ORDER BY / 列名无法参数化，直接拼接
async function getUsers(sortField: string) {
  const sql = `SELECT * FROM users ORDER BY ${sortField}`;
  return db.query(sql);
}

// 攻击：sortField = "id; DROP TABLE users--"
```

### 示例3（危险）：MongoDB 直接使用请求体

```typescript
// 危险：将 req.body 直接传入查询条件
app.post('/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password,  // 可能是 { $gt: "" }
  });
});
```

## 安全编码示例（推荐）

### 示例1：使用参数化查询（node-postgres）

```typescript
// 安全：使用占位符，驱动负责转义
async function getUserById(userId: string) {
  const sql = 'SELECT * FROM users WHERE id = $1';
  return db.query(sql, [userId]);
}
```

### 示例2：使用 ORM（TypeORM / Prisma）

```typescript
// 安全：TypeORM 参数化
const user = await userRepository.findOne({
  where: { id: userId },
});

// 安全：TypeORM QueryBuilder 参数化
const users = await userRepository
  .createQueryBuilder('user')
  .where('user.email = :email', { email: userEmail })
  .getMany();

// 安全：Prisma（天然参数化）
const user = await prisma.user.findUnique({
  where: { id: userId },
});
```

### 示例3：ORDER BY 白名单校验

```typescript
// 安全：动态列名必须走白名单，不能参数化
const ALLOWED_SORT_FIELDS = new Set(['id', 'name', 'created_at']);

async function getUsers(sortField: string) {
  if (!ALLOWED_SORT_FIELDS.has(sortField)) {
    throw new Error('非法排序字段');
  }
  const sql = `SELECT * FROM users ORDER BY ${sortField}`;
  return db.query(sql);
}
```

### 示例4：MongoDB 严格类型校验

```typescript
import { z } from 'zod';

const LoginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
});

app.post('/login', async (req, res) => {
  // 使用 zod 强制校验为字符串，阻断对象注入
  const { username, password } = LoginSchema.parse(req.body);
  const user = await db.collection('users').findOne({ username, password });
});
```

## 核心原则总结

- **参数化优先**：永远使用参数化查询或 ORM，禁止拼接用户输入到 SQL 字符串
- **列名/表名白名单**：无法参数化的动态部分（ORDER BY、列名）必须通过白名单校验
- **运行时类型校验**：对外部输入使用 `zod` 等 schema 验证，确保数据类型符合预期，防止 NoSQL 对象注入
- **最小权限**：数据库账号仅授予必要权限（SELECT/INSERT），禁止使用 root 账号
