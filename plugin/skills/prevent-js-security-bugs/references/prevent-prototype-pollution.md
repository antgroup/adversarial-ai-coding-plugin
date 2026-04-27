# 防范原型链污染安全编码规范

## 什么是原型链污染

JavaScript 中所有对象都通过原型链继承属性。原型链污染（Prototype Pollution）是指攻击者通过控制对象的键名（如 `__proto__`、`constructor`、`prototype`），在递归合并、深拷贝等操作中修改 `Object.prototype`，从而影响所有对象的属性，导致权限绕过、逻辑错误或远程代码执行。

**典型攻击场景1 —— 权限提升**

```
输入: { "__proto__": { "isAdmin": true } }
```
应用执行深合并后，所有对象的 `isAdmin` 属性变为 `true`，普通用户获得管理员权限。

**典型攻击场景2 —— 拒绝服务 / RCE（结合模板引擎）**

```
输入: { "__proto__": { "outputFunctionName": "x; process.mainModule.require('child_process').execSync('id')>/tmp/pwned; x" } }
```
污染 ejs 等模板引擎使用的内部属性，触发 RCE。

## 漏洞示例（禁止使用）

### 示例1（危险）：不安全的递归深合并

```typescript
// 危险：直接用键名赋值，__proto__ 会污染原型
function merge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // __proto__.isAdmin = true
    }
  }
  return target;
}

// 攻击：merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))
// 之后：({}).isAdmin === true
```

### 示例2（危险）：通过用户输入动态设置属性

```typescript
// 危险：键名来自用户输入，直接写入对象
app.post('/settings', (req, res) => {
  const config: any = {};
  const { key, value } = req.body;
  config[key] = value; // key = "__proto__"，value = {"isAdmin": true}
});
```


## 安全编码示例（推荐）

### 示例1：使用 hasOwnProperty 过滤危险键名

```typescript
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    if (DANGEROUS_KEYS.has(key)) continue; // 跳过危险键

    const srcVal = source[key];
    if (typeof srcVal === 'object' && srcVal !== null && !Array.isArray(srcVal)) {
      if (typeof target[key] !== 'object') target[key] = {};
      safeMerge(target[key] as Record<string, unknown>, srcVal as Record<string, unknown>);
    } else {
      target[key] = srcVal;
    }
  }
  return target;
}
```

### 示例2：使用 Object.create(null) 创建无原型对象

```typescript
// 安全：以 null 为原型的对象没有 __proto__，无法被污染
function parseConfig(userInput: string): Record<string, unknown> {
  const parsed = JSON.parse(userInput);
  const safe = Object.create(null) as Record<string, unknown>;

  for (const key of Object.keys(parsed)) {
    if (typeof key === 'string' && !['__proto__', 'constructor', 'prototype'].includes(key)) {
      safe[key] = parsed[key];
    }
  }
  return safe;
}
```

### 示例3：使用 structuredClone 深拷贝

```typescript
// 安全：structuredClone 是原生深拷贝，不会污染原型
const safeCopy = structuredClone(untrustedObject);
```



### 示例5：使用 Object.freeze 保护原型

```typescript
// 安全：冻结原型，使其属性不可被修改
Object.freeze(Object.prototype);
Object.freeze(Object);
Object.freeze(Function.prototype);
```

## 核心原则总结

- **过滤危险键名**：在递归合并前检查并跳过 `__proto__`、`constructor`、`prototype`
- **无原型对象**：处理外部 JSON 时使用 `Object.create(null)` 代替 `{}`
- **schema 白名单**：用 `zod`、`class-validator` 等工具只保留预期字段，自动丢弃危险键
- **更新依赖**：确保 lodash >= 4.17.21，及时修复含原型污染漏洞的第三方库
- **冻结原型**：在应用启动时 `Object.freeze(Object.prototype)` 作为纵深防御
