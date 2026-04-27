# 防范不安全传输（HTTP 明文通信）安全编码规范

## 什么是不安全传输漏洞

不安全传输是指应用通过 HTTP（而非 HTTPS）传输敏感数据，或动态加载外部资源（脚本、样式表）时使用 HTTP URL。中间人（MITM）攻击者可以：

1. **窃听**：读取明文传输的用户凭证、session token、个人数据
2. **篡改**：修改 HTTP 响应内容，向页面注入恶意脚本（Script Injection）
3. **降级攻击**：将 HTTPS 连接强制降级为 HTTP（SSL stripping）

**典型攻击场景 —— 脚本注入**

```
应用通过 HTTP 加载 jQuery：
<script src="http://cdn.example.com/jquery.min.js"></script>
攻击者劫持该 HTTP 响应，替换为含恶意代码的脚本，
所有访问该页面的用户浏览器都执行了攻击者的代码。
```

## 漏洞示例（禁止使用）

### 示例1（危险）：通过 HTTP 加载外部脚本

```html
<!-- 危险：HTTP 资源可被中间人替换 -->
<script src="http://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"></script>
<link rel="stylesheet" href="http://cdn.example.com/bootstrap.min.css">
```

### 示例2（危险）：服务端通过 HTTP 请求外部 API

```typescript
import http from 'http'; // 危险：使用 HTTP 模块而非 HTTPS

// 危险：明文传输 API key 和响应数据
http.get('http://api.external-service.com/data?key=SECRET', (res) => {
  // 数据在网络上明文传输
});
```

### 示例3（危险）：动态构造的 HTTP URL

```typescript
// 危险：URL 协议被硬编码为 http://
const apiUrl = `http://${process.env.API_HOST}/endpoint`;
fetch(apiUrl, { headers: { Authorization: `Bearer ${token}` } });
// token 将明文传输
```

### 示例4（危险）：混合内容（HTTPS 页面加载 HTTP 资源）

```javascript
// 危险：即使页面本身是 HTTPS，加载 HTTP 资源仍然不安全
// 现代浏览器会阻止此类混合内容，但旧版浏览器不会
const script = document.createElement('script');
script.src = 'http://analytics.example.com/tracker.js'; // 危险
document.head.appendChild(script);
```

## 安全编码示例（推荐）

### 示例1：始终使用 HTTPS URL

```html
<!-- 安全：HTTPS 加密传输 -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js"
        integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4="
        crossorigin="anonymous"></script>
```

### 示例2：服务端使用 https 模块或 fetch

```typescript
import https from 'https'; // 安全：使用 HTTPS 模块

// 推荐：使用 fetch（Node 18+）或 axios，默认支持 HTTPS
const response = await fetch('https://api.external-service.com/data', {
  headers: { Authorization: `Bearer ${token}` },
});

// 使用 https 模块时
https.get('https://api.external-service.com/data', (res) => {
  // 数据加密传输
});
```

### 示例3：强制 HTTPS 重定向（Express）

```typescript
import express from 'express';
import helmet from 'helmet';

const app = express();

// 安全：helmet 自动设置 HSTS 头，浏览器强制使用 HTTPS
app.use(helmet({
  hsts: {
    maxAge: 31536000, // 1年
    includeSubDomains: true,
    preload: true,
  },
}));

// 强制 HTTP 重定向到 HTTPS
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});
```

### 示例4：动态 URL 校验协议

```typescript
// 安全：对动态构造的 URL 校验协议
function makeApiCall(host: string, path: string): Promise<Response> {
  const url = new URL(path, `https://${host}`); // 强制 HTTPS

  // 额外校验：确保最终 URL 是 HTTPS
  if (url.protocol !== 'https:') {
    throw new Error('仅允许 HTTPS 请求');
  }

  return fetch(url.toString());
}
```

## 核心原则总结

- **所有外部通信必须使用 HTTPS**：无论是浏览器加载资源还是服务端发起请求，一律使用 `https://`
- **禁止在 HTTPS 页面加载 HTTP 资源**：混合内容（Mixed Content）既被浏览器拦截，也存在安全风险
- **外部脚本添加 SRI**：使用 `integrity` 属性（Subresource Integrity）校验脚本哈希，防止 CDN 被篡改
- **生产环境启用 HSTS**：通过 `Strict-Transport-Security` 响应头，指示浏览器永远使用 HTTPS 访问该域名
- **验证动态 URL 的协议**：对用户提供或环境变量中的 URL，使用 `new URL()` 解析并校验 `protocol === 'https:'`
