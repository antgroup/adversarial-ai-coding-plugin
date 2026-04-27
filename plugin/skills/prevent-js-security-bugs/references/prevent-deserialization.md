# 防范不安全反序列化安全编码规范

## 什么是不安全反序列化

不安全反序列化是指应用将来自用户的序列化数据（JSON、二进制、Base64 编码对象等）还原为对象时，使用了不安全的方式（如 `eval`、`new Function`、含 RCE 漏洞的第三方库），导致攻击者可以在服务端执行任意代码（RCE）。

**典型攻击场景1 —— eval 执行任意代码**

```
输入: {"name": "x", "toString": "function(){require('child_process').execSync('id>/tmp/pwned')}"}
应用使用 eval() 解析后，调用对象方法时触发代码执行。
```

**典型攻击场景2 -- new Function 执行任意代码**
TODO


## 漏洞示例（禁止使用）

### 示例1（危险）：eval 解析用户数据

```typescript
// 危险：eval 将字符串作为代码执行
app.post('/parse', (req, res) => {
  const data = req.body.payload;
  const obj = eval(`(${data})`); // 完全 RCE
  res.json(obj);
});
```

### 示例2（危险）：new Function 动态执行

```typescript
// 危险：new Function 与 eval 等价，同样可执行任意代码
function parseConfig(input: string) {
  return new Function(`return ${input}`)();
}
```

## 安全编码示例（推荐）

### 示例1：使用 JSON.parse + schema 验证

```typescript
import { z } from 'zod';

// 安全：JSON.parse 只还原数据，zod 验证结构和类型
const PayloadSchema = z.object({
  action: z.enum(['read', 'write', 'delete']),
  resourceId: z.string().uuid(),
  timestamp: z.number().int().positive(),
});

app.post('/action', (req, res) => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(req.body.payload);
  } catch {
    return res.status(400).send('无效的 JSON 格式');
  }

  const data = PayloadSchema.parse(parsed); // 验证通过才使用
  handleAction(data);
});
```

### 示例2：处理二进制序列化时使用 schema 验证（如 MessagePack / BSON）

```typescript
import msgpack from '@msgpack/msgpack';
import { z } from 'zod';

const EventSchema = z.object({
  type: z.string().max(50),
  userId: z.number().int(),
  data: z.record(z.string(), z.string()),
});

app.post('/event', (req, res) => {
  // 反序列化二进制数据
  const raw = msgpack.decode(req.body as Uint8Array);

  // 必须用 schema 验证反序列化结果
  const event = EventSchema.parse(raw);
  processEvent(event);
});
```


## 核心原则总结

- **禁用 eval / new Function**：永远不要用 `eval` 或 `new Function` 处理外部数据，这等同于直接执行用户代码
- **JSON.parse 是基准**：优先使用 `JSON.parse` 还原数据，它只处理数据类型，不执行代码
- **反序列化后必须验证**：`JSON.parse` 的结果类型为 `unknown`，必须用 `zod` 等 schema 工具验证结构和类型后才能使用