# 防范 PostMessage Origin 校验缺失安全编码规范

## 什么是 PostMessage Origin 校验缺失

`window.postMessage()` 是浏览器跨窗口/跨 iframe 通信的标准机制。当消息接收方不校验 `event.origin`（消息来源域名）时，任何页面（包括攻击者控制的恶意网站）都可以向目标窗口发送消息，诱导其执行危险操作（如转账、修改用户数据、读取敏感信息）。

**典型攻击场景1 —— 恶意父页面操控 iframe**

```
攻击者网站嵌入合法应用的 iframe，
向 iframe 发送伪造的 postMessage，
触发支付、数据删除等敏感操作。
```

**典型攻击场景2 —— 信息窃取**

```
目标页面监听 message 事件，将数据回传给 event.source，
但未校验 origin，攻击者通过弹窗获取到响应中的敏感数据。
```

## 漏洞示例（禁止使用）

### 示例1（危险）：不校验 origin 直接处理消息

```typescript
// 危险：任何来源的消息都会被处理
window.addEventListener('message', (event) => {
  const { action, payload } = event.data;
  if (action === 'transfer') {
    transferFunds(payload.amount, payload.to);
  }
});
```

### 示例2（危险）：origin 校验使用通配符

```typescript
// 危险：通配符 '*' 允许任意来源，与不校验等价
window.postMessage(sensitiveData, '*');

// 危险：接收方只检查 data 字段，忽略 origin
window.addEventListener('message', (event) => {
  if (event.data.type === 'AUTH_TOKEN') {
    localStorage.setItem('token', event.data.token); // 写入攻击者提供的 token
  }
});
```

### 示例3（危险）：origin 校验不严格

```typescript
// 危险：includes 检查可被绕过，如 evil-example.com
window.addEventListener('message', (event) => {
  if (event.origin.includes('example.com')) { // 可被 evil-example.com 绕过
    processCommand(event.data);
  }
});
```

## 安全编码示例（推荐）

### 示例1：严格校验 origin 白名单

```typescript
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://dashboard.example.com',
]);

window.addEventListener('message', (event) => {
  // 安全：精确匹配，使用 Set 查找防止旁路
  if (!ALLOWED_ORIGINS.has(event.origin)) {
    return; // 静默丢弃，不处理来自未知来源的消息
  }

  const { action, payload } = event.data;
  // 继续处理...
});
```

### 示例2：发送消息时指定精确目标 origin

```typescript
// 安全：指定精确的目标 origin，而非通配符 '*'
// 这样消息只会被目标窗口在指定 origin 下接收
const iframe = document.getElementById('payment-frame') as HTMLIFrameElement;
iframe.contentWindow?.postMessage(
  { type: 'PAYMENT_INIT', amount: 100 },
  'https://payment.example.com' // 明确指定，不用 '*'
);
```

### 示例3：完整的双向安全通信

```typescript
const PARENT_ORIGIN = 'https://parent.example.com';

// 子页面（iframe 内）
window.addEventListener('message', (event) => {
  if (event.origin !== PARENT_ORIGIN) return;

  // 验证消息结构
  if (typeof event.data !== 'object' || !event.data.type) return;

  switch (event.data.type) {
    case 'REQUEST_DATA':
      // 向父页面回复时也指定 origin
      event.source?.postMessage(
        { type: 'RESPONSE_DATA', data: getSafeData() },
        PARENT_ORIGIN
      );
      break;
    default:
      // 未知消息类型，忽略
  }
});
```

## 核心原则总结

- **接收方必须校验 `event.origin`**：使用精确字符串相等（`===`）或 `Set.has()` 进行白名单匹配，不用 `includes`/`startsWith` 等可被绕过的方法
- **发送方必须指定目标 origin**：`postMessage(data, targetOrigin)` 第二参数不得为 `'*'`，应填写精确的目标域名（含协议和端口）
- **不信任 event.data 的结构**：即使 origin 合法，也应校验消息格式，防止合法源被 XSS 污染后发出恶意消息
- **静默丢弃非法消息**：origin 不匹配时直接 `return`，不抛出异常（避免信息泄露）
