# 防范弱随机数生成安全编码规范

## 什么是弱随机数漏洞

JavaScript 内置的 `Math.random()` 和 Node.js 旧版的 `crypto.pseudoRandomBytes()` 使用伪随机数生成器（PRNG），其输出是可预测的。当这类弱随机数被用于生成 session ID、token、nonce、密钥、UUID 等安全敏感值时，攻击者可以通过统计分析或暴力枚举预测出这些值，从而伪造身份、绕过认证或破解加密。

**典型攻击场景1 —— 可预测的 session token**

```
Math.random() 内部状态可被推断，攻击者观察若干 token 后，
即可预测下一个用户的 session ID，实现会话劫持。
```

**典型攻击场景2 —— 弱 nonce 导致重放攻击**

```
nonce = Math.random().toString(36) // 熵不足，暴力枚举可行
攻击者枚举 nonce 空间，绕过一次性令牌保护
```

## 漏洞示例（禁止使用）

### 示例1（危险）：用 Math.random() 生成 token

```typescript
// 危险：Math.random() 是伪随机，不具备密码学安全性
function generateSessionToken(): string {
  return Math.random().toString(36).substring(2);
}

// 危险：通过拼接多个 Math.random() 也无法增加安全性
function generateApiKey(): string {
  return Math.random().toString(36).substring(2) +
         Math.random().toString(36).substring(2);
}
```

### 示例2（危险）：用 pseudoRandomBytes 生成密钥

```typescript
import crypto from 'crypto';

// 危险：pseudoRandomBytes 已废弃，等同于 Math.random()，不具备密码学强度
function generateKey(): Buffer {
  return crypto.pseudoRandomBytes(32);
}
```

## 安全编码示例（推荐）

### 示例1：使用 crypto.randomBytes 生成 token

```typescript
import crypto from 'crypto';

// 安全：randomBytes 使用操作系统的密码学安全随机源（/dev/urandom 或 CryptGenRandom）
function generateSessionToken(): string {
  return crypto.randomBytes(32).toString('hex'); // 64字符十六进制
}

function generateApiKey(): string {
  return crypto.randomBytes(24).toString('base64url'); // URL安全的Base64
}
```

### 示例2：使用 crypto.randomUUID 生成 UUID（Node 14.17+）

```typescript
import crypto from 'crypto';

// 安全：Node.js 原生密码学安全 UUID v4
const id = crypto.randomUUID(); // 标准 UUID v4，基于密码学随机源
```

### 示例3：使用 crypto.getRandomValues（浏览器端）

```typescript
// 安全：Web Crypto API，浏览器端密码学安全随机数
function generateToken(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}
```

### 示例4：Math.random() 的合法使用场景

```typescript
// 合法：非安全场景下（UI 动画、随机颜色、游戏逻辑），Math.random() 是可接受的
const randomColor = `#${Math.floor(Math.random() * 0xffffff).toString(16)}`;
const randomIndex = Math.floor(Math.random() * items.length);
```

## 核心原则总结

- **安全敏感场景必须使用密码学安全随机源**：凡涉及 session ID、token、nonce、UUID、密钥、验证码、密码重置链接，一律使用 `crypto.randomBytes()`（Node.js）或 `crypto.getRandomValues()`（浏览器）
- **禁止 Math.random() 用于安全用途**：即使多次调用或加盐也无法补救其可预测性
- **pseudoRandomBytes 已废弃**：`crypto.pseudoRandomBytes` 等同于弱随机，直接替换为 `crypto.randomBytes`
- **区分使用场景**：纯 UI/游戏逻辑中 `Math.random()` 无害；任何用于唯一性保证、防重放、认证的场景均属安全敏感
