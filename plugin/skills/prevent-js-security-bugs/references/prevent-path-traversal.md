# 防范路径遍历安全编码规范

## 什么是路径遍历

路径遍历（Path Traversal）是指攻击者通过在文件名或路径参数中注入 `../`（或其编码形式 `%2e%2e%2f`）来跳出预期目录，访问服务器上任意文件，包括配置文件、密钥、系统文件（如 `/etc/passwd`）。

**典型攻击场景1 —— 文件下载接口**

```
请求: GET /download?file=../../../etc/passwd
构造路径: /var/app/uploads/../../../etc/passwd → /etc/passwd
```
攻击者读取系统账号文件。

**典型攻击场景2 —— URL 编码绕过**

```
请求: GET /file?name=..%2F..%2F..%2Fetc%2Fshadow
```
应用只过滤了字面量 `../` 但未解码，攻击者通过 URL 编码绕过过滤。

## 漏洞示例（禁止使用）

### 示例1（危险）：path.join 拼接用户输入后直接使用

```typescript
import path from 'path';
import fs from 'fs/promises';

// 危险：path.join 会规范化路径，但不阻止跨越基准目录
app.get('/file', async (req, res) => {
  const filename = req.query.name as string;
  const filePath = path.join('/var/app/uploads', filename);
  // filename = "../../etc/passwd" → filePath = "/etc/passwd"
  const content = await fs.readFile(filePath);
  res.send(content);
});
```

### 示例2（危险）：仅过滤字面量 ../

```typescript
// 危险：只替换 "../" 无法防御 URL 编码、双重编码等变体
function sanitizePath(input: string): string {
  return input.replace(/\.\.\//g, ''); // ..%2F 可以绕过
}
```

### 示例3（危险）：直接使用 req.params 构造路径

```typescript
// 危险：Express 路由参数未校验直接用于文件操作
app.get('/logs/:filename', (req, res) => {
  const filePath = `/var/log/app/${req.params.filename}`;
  res.sendFile(filePath);
});
```

## 安全编码示例（推荐）

### 示例1：path.resolve + 前缀校验（核心防御手段）

```typescript
import path from 'path';
import fs from 'fs/promises';

const BASE_DIR = '/var/app/uploads';

app.get('/file', async (req, res) => {
  const filename = req.query.name as string;

  // path.resolve 将路径解析为绝对路径（会处理 ../ 和编码）
  const resolvedPath = path.resolve(BASE_DIR, filename);

  // 校验解析后的路径必须以基准目录开头
  if (!resolvedPath.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).send('禁止访问');
  }

  try {
    const content = await fs.readFile(resolvedPath);
    res.send(content);
  } catch {
    res.status(404).send('文件不存在');
  }
});
```

### 示例2：白名单文件名格式校验

```typescript
import path from 'path';

// 安全：只允许字母、数字、连字符、下划线、点，且只允许特定扩展名
function isValidFilename(filename: string): boolean {
  // 不允许路径分隔符和 ..
  if (filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
    return false;
  }
  // 只允许安全字符和指定扩展名
  return /^[\w\-]+\.(pdf|png|jpg|jpeg|txt|csv)$/.test(filename);
}

app.get('/download', async (req, res) => {
  const filename = String(req.query.file ?? '');

  if (!isValidFilename(filename)) {
    return res.status(400).send('非法文件名');
  }

  const filePath = path.join('/var/app/uploads', filename);
  res.download(filePath);
});
```



## 核心原则总结

- **resolve + 前缀校验**：使用 `path.resolve()` 解析绝对路径后，检查是否以允许的基准目录开头，这是最可靠的防御手段
- **白名单文件名**：对文件名用正则白名单，只允许安全字符集和指定扩展名，拒绝包含 `/`、`\`、`..` 的输入
- **不依赖黑名单过滤**：过滤 `../` 的方法容易被 URL 编码（`%2e%2e%2f`）、双重编码等绕过，不可靠
