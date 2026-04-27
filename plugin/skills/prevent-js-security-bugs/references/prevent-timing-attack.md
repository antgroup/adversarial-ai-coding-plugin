# 防范时序攻击安全编码规范

## 什么是时序攻击

时序攻击（Timing Attack）是一种侧信道攻击。普通的字符串比较（`===`、`!==`）会在发现第一个不匹配字符时立即返回，导致比较耗时随"正确前缀长度"变化。攻击者通过精确测量响应时间，可以逐字节猜测出正确的密钥、token 或密码，而无需暴力枚举整个空间。

**典型攻击场景 —— HMAC 签名验证**

```
攻击者提交不同的签名字符串，测量服务器响应时间：
- "a..." → 立即返回（第1位错）→ 耗时 1μs
- "s..." → 稍慢返回（第1位对）→ 耗时 2μs
通过此差异逐位猜测，最终还原出正确签名。
```

## 漏洞示例（禁止使用）

### 示例1（危险）：用 === 比较 HMAC 签名

```typescript
import crypto from 'crypto';

// 危险：=== 会短路，攻击者可通过时间差逐位猜测签名
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-signature'] as string;
  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET!)
    .update(req.rawBody)
    .digest('hex');

  if (signature === expected) { // 漏洞：非常数时间比较
    processWebhook(req.body);
    res.sendStatus(200);
  } else {
    res.sendStatus(401);
  }
});
```

### 示例2（危险）：比较密码重置 token

```typescript
// 危险：直接字符串比较 token
function validateResetToken(inputToken: string, storedToken: string): boolean {
  return inputToken === storedToken; // 时序漏洞
}
```

### 示例3（危险）：API Key 比较

```typescript
// 危险：早退出的比较泄露信息
function authenticate(apiKey: string): boolean {
  return apiKey === process.env.API_KEY; // 时序漏洞
}
```

## 安全编码示例（推荐）

### 示例1：使用 crypto.timingSafeEqual 比较签名

```typescript
import crypto from 'crypto';

// 安全：timingSafeEqual 始终遍历完整个缓冲区，耗时恒定
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-signature'] as string;
  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET!)
    .update(req.rawBody)
    .digest('hex');

  // 注意：timingSafeEqual 要求两个 Buffer 长度相同
  // 先将字符串转换为 Buffer，且长度必须一致才能比较
  const sigBuffer = Buffer.from(signature);
  const expBuffer = Buffer.from(expected);

  if (sigBuffer.length !== expBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
    return res.sendStatus(401);
  }

  processWebhook(req.body);
  res.sendStatus(200);
});
```

### 示例2：安全比较任意 token

```typescript
import crypto from 'crypto';

// 安全：通用常数时间比较函数
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  // 长度不同时也需要常数时间，通过比较哈希值来实现
  if (bufA.length !== bufB.length) {
    // 仍然执行一次 timingSafeEqual，防止长度本身泄露信息
    crypto.timingSafeEqual(bufA, bufA); // dummy operation
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

// 使用
function validateResetToken(inputToken: string, storedToken: string): boolean {
  return safeCompare(inputToken, storedToken);
}
```

### 示例3：密码验证使用 bcrypt/argon2（自带常数时间）

```typescript
import bcrypt from 'bcrypt';

// 安全：bcrypt.compare 内部使用常数时间比较，同时处理哈希验证
async function verifyPassword(plaintext: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plaintext, hash); // 安全，自带时序保护
}
```

## 需要常数时间比较的场景清单

以下场景**必须**使用 `crypto.timingSafeEqual` 或等价库函数：

| 场景 | 说明 |
|------|------|
| HMAC / 数字签名验证 | Webhook 签名、JWT 签名 |
| API Key 认证 | 比较请求中的 key 与存储值 |
| 密码重置 token | 邮件/短信发送的一次性 token |
| CSRF token | 表单防御 token 验证 |
| Cookie 值比较 | 会话 cookie、记住我 token |

## 核心原则总结

- **禁止用 `===`/`!==` 比较安全敏感字符串**：所有 token、签名、密钥的比较必须使用 `crypto.timingSafeEqual()`
- **密码验证用专用库**：`bcrypt.compare()`、`argon2.verify()` 已内置常数时间比较，不要自行实现
- **长度不同时也要常数时间**：长度检查本身也可泄露信息，处理方式是先做 dummy 操作再返回 false
- **注意 Buffer 编码一致**：传入 `timingSafeEqual` 的两个 Buffer 必须使用相同编码（都是 hex、都是 utf8 等）
