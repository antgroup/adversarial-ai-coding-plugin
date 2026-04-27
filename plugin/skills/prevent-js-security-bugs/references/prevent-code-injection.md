# 防范代码注入安全编码规范

## 什么是代码注入

代码注入是指应用将不可信数据传入代码执行机制（`eval`、`new Function`、`setTimeout(string)`、动态 `require()`），导致攻击者可以在服务端执行任意 JavaScript，或在客户端触发 XSS。与 OS 命令注入不同，代码注入直接在 JavaScript 运行时内部执行，无需 Shell 中间层，危害更直接。

**典型攻击场景1 —— eval 执行用户输入**

```
input = "process.mainModule.require('child_process').execSync('rm -rf /')"
eval(input)  →  直接在 Node.js 进程内删除文件
```

**典型攻击场景2 —— 动态 require 读取任意文件**

```
require('/etc/passwd')  →  读取第一行（Node.js 会尝试解析为模块）
require(userControlledPath)  →  执行攻击者上传的恶意脚本
```

**典型攻击场景3 —— new Function 绕过沙箱**

```
new Function('return process.env')()  →  泄露所有环境变量（含密钥）
```

## 漏洞示例（禁止使用）

### 示例1（危险）：eval 执行用户提供的表达式

```typescript
// 危险：eval 直接在当前作用域执行任意代码
app.post('/calc', (req, res) => {
  const expr = req.body.expression;
  const result = eval(expr); // 高危：RCE
  res.json({ result });
});
```

### 示例2（危险）：new Function 构造动态函数

```typescript
// 危险：new Function 与 eval 等价，可访问 global 作用域
function createSorter(comparatorCode: string) {
  return new Function('a', 'b', comparatorCode); // 高危
}
// 攻击：comparatorCode = "return process.env.SECRET_KEY.length"
```

### 示例3（危险）：动态 require 路径来自用户输入

```typescript
// 危险：攻击者可通过路径遍历加载任意文件
app.get('/plugin', (req, res) => {
  const pluginName = req.query.name as string;
  const plugin = require(`./plugins/${pluginName}`); // 路径注入 + 代码注入
  res.json(plugin.getInfo());
});
```

### 示例4（危险）：setTimeout/setInterval 传入字符串

```typescript
// 危险：setTimeout 接受字符串时等同于 eval
setTimeout(`sendData(${userInput})`, 1000); // 高危
```

## 安全编码示例（推荐）

### 示例1：用数学库替代 eval 计算表达式

```typescript
import { create, all } from 'mathjs';

const math = create(all);

// 安全：mathjs 在沙箱中求值，禁止访问 process、require 等危险对象
app.post('/calc', (req, res) => {
  const expr = req.body.expression as string;
  try {
    const result = math.evaluate(expr);
    res.json({ result });
  } catch {
    res.status(400).json({ error: '表达式无效' });
  }
});
```

### 示例2：用白名单映射替代动态 require

```typescript
// 安全：使用 Object.create(null) 创建无原型的注册表，
// 防止攻击者传入 "__proto__" / "constructor" 等键绕过白名单
const PLUGIN_REGISTRY = Object.assign(Object.create(null), {
  'csv-parser': require('./plugins/csv-parser'),
  'xml-parser': require('./plugins/xml-parser'),
  'json-formatter': require('./plugins/json-formatter'),
}) as Record<string, object>;

app.get('/plugin', (req, res) => {
  const pluginName = req.query.name as string;

  // 使用 hasOwnProperty 安全检查，而非直接属性访问
  if (!Object.prototype.hasOwnProperty.call(PLUGIN_REGISTRY, pluginName)) {
    return res.status(404).json({ error: '插件不存在' });
  }

  res.json(PLUGIN_REGISTRY[pluginName]);
});
```


### 示例3：setTimeout/setInterval 始终传函数

```typescript
// 安全：传入函数引用，而非字符串
setTimeout(() => sendData(sanitizedInput), 1000); // 安全
setInterval(() => checkStatus(), 5000); // 安全

// 禁止：
// setTimeout(`sendData(${userInput})`, 1000); // 危险
```

## 核心原则总结

- **禁止 `eval()`**：任何场景都不应将外部数据传入 eval；内部常量字符串也应避免，保持习惯
- **禁止 `new Function(userInput, ...)`**：new Function 与 eval 等价，同样可访问全局作用域
- **禁止动态 `require(nonLiteralPath)`**：插件/模块加载必须使用预定义白名单映射
- **setTimeout/setInterval 只传函数**：永远不传字符串参数