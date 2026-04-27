# 防范正则表达式拒绝服务（ReDoS）安全编码规范

## 什么是 ReDoS

ReDoS（Regular Expression Denial of Service）利用正则引擎的回溯机制。当使用包含嵌套量词或交替分支的正则表达式，对特定构造的输入字符串进行匹配时，回溯次数会呈指数级增长，导致 CPU 长时间占用（数秒乃至数分钟），使整个 Node.js 应用无法响应其他请求（单线程阻塞）。

当正则表达式由用户输入动态构造（`new RegExp(userInput)`）时，攻击者可精心设计恶意 payload 来触发灾难性回溯。

**典型攻击场景 —— 动态正则被恶意 payload 触发**

```
正则: /^(a+)+$/
输入: "aaaaaaaaaaaaaaaaaaaaaaaab"  (30个a + 非匹配字符)
回溯: 2^30 次 ≈ 10亿次，服务崩溃
```

## 漏洞示例（禁止使用）

### 示例1（危险）：直接用用户输入构造 RegExp

```typescript
// 危险：用户可构造灾难性回溯的正则
app.get('/search', (req, res) => {
  const pattern = req.query.pattern as string;
  const regex = new RegExp(pattern); // 高危：攻击者控制正则
  const results = data.filter(item => regex.test(item));
  res.json(results);
});
```

### 示例2（危险）：将用户输入嵌入正则模板

```typescript
// 危险：即使只是局部插入，也可能引入危险结构
function searchByExtension(ext: string) {
  const regex = new RegExp(`\\.${ext}$`); // ext 若为 "(a+)+" 则可触发 ReDoS
  return files.filter(f => regex.test(f));
}
```

### 示例3（危险）：使用用户输入的 flags

```typescript
// 危险：flags 也可能被篡改（如传入非法 flag 导致异常或 ReDoS）
const regex = new RegExp(userPattern, userFlags);
```

## 安全编码示例（推荐）

### 示例1：转义用户输入，仅作字面量匹配

```typescript
// 安全：将用户输入作为字面量字符串，而非正则语法
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

app.get('/search', (req, res) => {
  const query = req.query.q as string;
  const safePattern = escapeRegExp(query);
  const regex = new RegExp(safePattern, 'i'); // 字面量搜索，无回溯风险
  const results = data.filter(item => regex.test(item));
  res.json(results);
});
```

### 示例2：使用字符串方法替代动态正则

```typescript
// 安全：简单的搜索场景直接用字符串方法，完全避免正则
app.get('/search', (req, res) => {
  const query = (req.query.q as string).toLowerCase();
  const results = data.filter(item =>
    item.toLowerCase().includes(query) // 无正则，无回溯
  );
  res.json(results);
});
```

### 示例3：用 re2 库检测/替代危险正则

```typescript
import RE2 from 're2'; // 基于 Google RE2，线性时间复杂度，无灾难性回溯

// 安全：RE2 引擎保证线性时间，即使面对恶意输入也不会超时
function safeMatch(pattern: string, input: string): boolean {
  try {
    const regex = new RE2(pattern);
    return regex.test(input);
  } catch {
    return false; // 非法正则语法，安全拒绝
  }
}
```

### 示例4：对固定正则也要避免危险模式

```typescript
// 危险正则模式（即使不来自用户输入，也要避免）：
// /^(a+)+$/          嵌套量词
// /(a|aa)*b$/          重叠交替
// /([a-zA-Z]+)*$/    带量词的字符类组

// 安全替代：简化量词结构，避免嵌套和重叠交替
// /^a+$/             单层量词，安全
// /^[a-zA-Z]+$/      字符类不嵌套，安全
```

## 核心原则总结

- **禁止将用户输入直接传入 `new RegExp()`**：若必须支持用户自定义搜索，先用 `escapeRegExp` 转义再构造，或限定为字面量字符串匹配
- **优先使用字符串方法**：`includes()`、`startsWith()`、`indexOf()` 在简单搜索场景下更安全高效
- **高风险场景使用 RE2**：若业务确实需要用户提供正则，使用 `re2` 库（线性时间引擎）替代内置 `RegExp`
- **审查自写正则**：避免嵌套量词（`(a+)+`）、重叠交替（`(a|aa)+`）等已知危险模式
- **设置超时兜底**：在无法完全消除风险时，使用 worker thread + 超时终止作为最后防线
