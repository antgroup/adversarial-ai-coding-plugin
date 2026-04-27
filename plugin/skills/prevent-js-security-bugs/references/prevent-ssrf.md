# 防范 SSRF（服务端请求伪造）安全编码规范

## 什么是 SSRF

SSRF（Server-Side Request Forgery，服务端请求伪造）是指攻击者控制服务端发起 HTTP 请求的目标地址，使服务器向内网服务、云元数据接口（如 AWS `169.254.169.254`）或本地服务（`localhost`）发起请求，从而泄露内网信息、绕过防火墙或获取云凭证。

**典型攻击场景1 —— 访问云元数据接口**

```
用户提交: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
服务器请求该地址，返回 AWS IAM 临时凭证，攻击者获得云账号访问权限。
```

**典型攻击场景2 —— 探测内网服务**

```
用户提交: url = "http://192.168.1.1/admin"
服务器向内网路由器管理页面发起请求，攻击者获取内网拓扑或敏感数据。
```

## 漏洞示例（禁止使用）

### 示例1（危险）：直接使用用户提供的 URL 发起请求

```typescript
// 危险：url 完全由用户控制
app.post('/fetch-url', async (req, res) => {
  const { url } = req.body;
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});
```

### 示例2（危险）：Webhook 回调地址未校验

```typescript
// 危险：将用户设置的 webhook 地址用于服务端回调
async function sendWebhook(webhookUrl: string, payload: object) {
  await fetch(webhookUrl, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}
```

## 安全编码示例（推荐）

### 示例1：域名白名单校验

```typescript
import { URL } from 'url';

const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

function validateUrl(rawUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('非法 URL 格式');
  }

  // 只允许 https 协议
  if (parsed.protocol !== 'https:') {
    throw new Error('只允许 HTTPS 请求');
  }

  // 主机名白名单
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error(`不允许请求主机：${parsed.hostname}`);
  }

  return parsed;
}

app.post('/fetch-url', async (req, res) => {
  const safeUrl = validateUrl(req.body.url);
  const response = await fetch(safeUrl.toString());
  res.send(await response.text());
});
```

### 示例2：解析 IP 并阻断内网地址

```typescript
import dns from 'dns/promises';
import { isIP } from 'net';

// 检查 IP 是否属于私有/保留地址
function isPrivateIp(ip: string): boolean {
  const privateRanges = [
    /^127\./,                          // loopback
    /^10\./,                           // RFC 1918
    /^172\.(1[6-9]|2\d|3[01])\./,     // RFC 1918
    /^192\.168\./,                     // RFC 1918
    /^169\.254\./,                     // link-local（云元数据）
    /^::1$/,                           // IPv6 loopback
    /^fc00:/i,                         // IPv6 unique local
    /^fe80:/i,                         // IPv6 link-local
  ];
  return privateRanges.some(re => re.test(ip));
}

async function safeRequest(rawUrl: string): Promise<Response> {
  const parsed = new URL(rawUrl);

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('不支持的协议');
  }

  // 解析域名对应的 IP 并检查是否为内网地址
  const hostname = parsed.hostname;
  const addresses = isIP(hostname)
    ? [hostname]
    : await dns.resolve4(hostname).catch(() => [] as string[]);

  if (addresses.length === 0) {
    throw new Error('域名解析失败');
  }
  for (const ip of addresses) {
    if (isPrivateIp(ip)) {
      throw new Error(`禁止访问内网地址：${ip}`);
    }
  }

  return fetch(rawUrl);
}
```


## 核心原则总结

- **域名白名单**：对允许请求的外部服务维护严格白名单，拒绝白名单之外的所有主机
- **IP 黑名单**：解析域名后检查目标 IP，阻断对私有地址段（RFC 1918、169.254.x.x、::1）的请求
- **协议限制**：只允许 `http:` 和 `https:`，禁止 `file:`、`gopher:`、`dict:` 等协议
- **禁用重定向**：发起请求时禁用自动重定向（`maxRedirects: 0`），防止绕过 IP 检查后通过重定向访问内网
