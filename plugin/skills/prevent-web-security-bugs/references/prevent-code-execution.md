# 防范代码执行安全编码规范

## 什么是代码执行漏洞

代码执行漏洞（Code Execution）是指应用程序将用户可控的输入作为代码进行动态解析和执行，攻击者通过构造恶意表达式或脚本，在服务端执行任意代码，从而完全控制服务器。常见的代码执行场景包括：

- **Groovy 脚本执行**：使用 `GroovyShell`、`GroovyClassLoader` 动态执行用户输入的 Groovy 脚本
- **Spring Expression Language（SpEL）注入**：将用户输入拼接进 SpEL 表达式并求值
- **JavaScript 引擎执行**：使用 `ScriptEngine`（Nashorn/Rhino）执行用户输入的 JS 代码
- **Python eval/exec 执行**：使用 `eval()`、`exec()` 执行用户输入的 Python 代码

**典型攻击场景**：
- 规则引擎接口：将用户配置的规则字符串直接传入 `GroovyShell.evaluate()`
- 动态表达式计算：将用户输入拼接进 SpEL 表达式 `#{userInput}` 并求值
- 模板预览接口：将用户输入传入 `eval()` 计算动态内容

---

## 漏洞示例（禁止使用）

### Groovy 脚本直接执行用户输入（危险）

```java
// ❌ 危险：直接执行用户传入的 Groovy 脚本
@PostMapping("/execute")
public Object executeScript(@RequestBody String script) {
    GroovyShell shell = new GroovyShell();
    return shell.evaluate(script);  // 攻击者可执行任意代码
}
```

### SpEL 表达式拼接用户输入（危险）

```java
// ❌ 危险：将用户输入拼接进 SpEL 表达式求值
@GetMapping("/calc")
public Object calculate(@RequestParam String expression) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(expression);  // 攻击者可注入 T(Runtime).getRuntime().exec('...')
    return exp.getValue();
}
```

### Python eval 执行用户输入（危险）

```python
# ❌ 危险：使用 eval 执行用户输入
@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    result = eval(expression)  # 攻击者可执行任意 Python 代码
    return str(result)
```

### JavaScript 引擎执行用户输入（危险）

```java
// ❌ 危险：使用 ScriptEngine 执行用户输入的 JS 代码
ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
engine.eval(userInput);  // 攻击者可访问 Java 类执行系统命令
```

---

## 安全编码示例（推荐）

### 安全编码原则：避免动态执行用户输入的脚本，优先使用配置化方案

```java
// ✅ 安全：将业务规则抽象为配置，而非动态脚本
// 用枚举或策略模式替代动态脚本执行
public enum DiscountRule {
    PERCENTAGE {
        @Override
        public double apply(double price, double param) {
            return price * (1 - param / 100);
        }
    },
    FIXED_AMOUNT {
        @Override
        public double apply(double price, double param) {
            return Math.max(0, price - param);
        }
    };

    public abstract double apply(double price, double param);
}

// 根据用户选择的规则类型（枚举值）执行，而非执行用户输入的脚本
DiscountRule rule = DiscountRule.valueOf(userSelectedRuleType);
double finalPrice = rule.apply(originalPrice, ruleParam);
```

如果业务确实需要执行动态脚本，必须配置安全管理器或使用沙箱机制，限制脚本可访问的类和操作。


### SpEL：使用 SimpleEvaluationContext 限制表达式能力

`SimpleEvaluationContext` 不支持 Java 类型引用、构造函数调用等高危操作，适用于只需要简单属性访问和运算的场景。

```java
// ✅ 安全：使用 SimpleEvaluationContext 替代 StandardEvaluationContext
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();

// 仅支持属性访问和基本运算，无法调用 T(Runtime) 等危险表达式
Expression exp = parser.parseExpression(expression);
Object result = exp.getValue(context, dataObject);
```

### Python：使用 AST 安全解析替代 eval

对于只需要计算数学表达式的场景，使用 `ast.literal_eval` 或专用的数学表达式库替代 `eval`。

```python
# ✅ 安全：使用 ast.literal_eval 仅解析字面量（字符串、数字、列表等）
import ast

@app.route('/parse')
def parse_value():
    raw_value = request.args.get('value')
    # literal_eval 只能解析字面量，无法执行任意代码
    result = ast.literal_eval(raw_value)
    return str(result)
```

```python
# ✅ 安全：使用专用数学表达式库（如 simpleeval）替代 eval
from simpleeval import simple_eval

@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    # simple_eval 只支持数学运算，不支持函数调用和模块访问
    result = simple_eval(expression)
    return str(result)
```

---
