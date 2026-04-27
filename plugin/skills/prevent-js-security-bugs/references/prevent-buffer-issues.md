# 防范 Node.js Buffer 安全问题编码规范

## 什么是 Buffer 安全问题

Node.js 的 Buffer API 历史上存在多个安全缺陷，主要涉及三类问题：

1. **`new Buffer(size)` 内存未初始化（CWE-908）**：旧版 Buffer 构造函数分配内存时不清零，新 Buffer 可能包含其他进程遗留的敏感数据（密码、密钥），被读取后造成信息泄露。

2. **`Buffer.allocUnsafe()` 信息泄露（CWE-908）**：与 `new Buffer(size)` 同理，分配未初始化内存，读取内容可能泄露堆中历史数据。

3. **`noAssert` 参数越界访问（CWE-119）**：Buffer 读写方法（如 `readUInt32BE`、`writeInt8`）的 `noAssert` 参数（Node 10 起废弃）会跳过边界检查，允许访问 Buffer 范围外的内存，导致崩溃或信息泄露。

## 漏洞示例（禁止使用）

### 示例1（危险）：new Buffer() 构造未初始化 Buffer

```typescript
// 危险：已废弃的构造函数，分配未初始化内存
// 若 size 来自用户输入，攻击者可读取堆中遗留的敏感数据
const size = parseInt(req.query.size as string);
const buf = new Buffer(size); // 高危，CWE-908
res.send(buf); // 可能返回包含密码/密钥的内存内容
```

### 示例2（危险）：allocUnsafe 结果直接暴露

```typescript
// 危险：allocUnsafe 分配未初始化内存
function createResponseBuffer(size: number): Buffer {
  const buf = Buffer.allocUnsafe(size); // 包含随机堆数据
  // 忘记填充数据，直接返回
  return buf; // 泄露历史内存内容
}
```

### 示例3（危险）：使用 noAssert 跳过边界检查

```typescript
// 危险：noAssert=true 跳过偏移量边界验证
// offset 超出 buffer 长度时不报错，直接越界读写
function parsePacket(buf: Buffer, offset: number) {
  const value = buf.readUInt32BE(offset, true); // true = noAssert，废弃且危险
  return value;
}
```

## 安全编码示例（推荐）

### 示例1：使用 Buffer.alloc() 替代 new Buffer()

```typescript
// 安全：Buffer.alloc 分配已清零的内存，防止历史数据泄露
const buf = Buffer.alloc(1024); // 所有字节初始化为 0

// 安全：需要特定填充值时
const buf2 = Buffer.alloc(1024, 0xff); // 填充为 0xff
```

### 示例2：allocUnsafe 必须立即完整填充

```typescript
// 如果出于性能原因必须用 allocUnsafe，必须在任何读取前完整写入
function buildPacket(data: Uint8Array): Buffer {
  const buf = Buffer.allocUnsafe(data.length); // 仅性能优化时使用
  data.copy(buf); // 立即完整覆盖，确保无未初始化字节
  return buf;
}

// 更好：绝大多数场景用 Buffer.from() 直接从已知数据创建
const buf = Buffer.from(data); // 安全，自动复制内容
```

### 示例3：移除 noAssert，使用边界校验

```typescript
// 安全：不传 noAssert，让 Node.js 进行边界检查
function parsePacket(buf: Buffer, offset: number): number {
  // 先手动校验，再读取
  if (offset < 0 || offset + 4 > buf.length) {
    throw new RangeError(`偏移量 ${offset} 超出 Buffer 范围`);
  }
  return buf.readUInt32BE(offset); // 不传第二参数，默认 noAssert=false
}
```

### 示例4：处理用户控制的 Buffer size

```typescript
const MAX_BUFFER_SIZE = 1024 * 1024; // 1MB 上限，防止内存耗尽

app.get('/data', (req, res) => {
  const size = parseInt(req.query.size as string, 10);

  // 校验 size 合法性，防止 NaN、负数、超大值
  if (!Number.isInteger(size) || size <= 0 || size > MAX_BUFFER_SIZE) {
    return res.status(400).send('非法 size 参数');
  }

  const buf = Buffer.alloc(size); // 安全：已清零
  // 填充合法数据后再返回
  res.send(buf);
});
```

## Buffer API 安全速查表

| 用法 | 安全性 | 推荐替代 |
|------|--------|----------|
| `new Buffer(size)` | 危险，已废弃 | `Buffer.alloc(size)` |
| `new Buffer(string)` | 危险，已废弃 | `Buffer.from(string, encoding)` |
| `Buffer.allocUnsafe(size)` | 谨慎，需立即填充 | `Buffer.alloc(size)` |
| `buf.readXxx(offset, true)` | 危险，noAssert 废弃 | `buf.readXxx(offset)` |
| `Buffer.alloc(size)` | 安全 | — |
| `Buffer.from(data)` | 安全 | — |

## 核心原则总结

- **禁止使用 `new Buffer()`**：无论传入数字还是字符串，一律改用 `Buffer.alloc()` 或 `Buffer.from()`
- **谨慎使用 `Buffer.allocUnsafe()`**：仅在性能关键路径使用，且必须在返回前完整写入所有字节
- **禁止 `noAssert` 参数**：移除所有 Buffer 读写方法中的第二个 `true` 参数（如 `readUInt32BE(offset, true)`）
- **限制用户控制的 size**：校验上下界、整数性，防止内存耗尽（DoS）和未初始化内存泄露
