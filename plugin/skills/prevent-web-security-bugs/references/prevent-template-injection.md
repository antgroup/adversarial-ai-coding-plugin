# 防范模板注入安全编码规范

## 什么是模板注入

服务端模板注入（Server-Side Template Injection，SSTI）是指应用程序将用户可控的输入直接拼接进模板字符串并进行渲染，攻击者通过构造特殊的模板语法，使模板引擎执行恶意代码，从而读取服务器敏感信息、执行系统命令，甚至完全控制服务器。常见的受影响模板引擎包括：

- **FreeMarker**：Java 生态常用模板引擎，支持 `?new()`、`freemarker.template.utility.Execute` 等危险特性
- **Velocity**：Java 生态模板引擎，支持通过 `$class.inspect` 访问 Java 类
- **Thymeleaf**：Spring 生态模板引擎，在某些配置下支持 SpEL 表达式
- **Jinja2**：Python Flask/Django 常用模板引擎，支持访问 Python 对象属性和方法

**典型攻击场景**：
- 邮件模板接口：将用户输入的邮件正文直接传入 `Template.process()` 渲染
- 报告生成接口：将用户自定义的报告模板字符串直接渲染
- FreeMarker 注入：`${freemarker.template.utility.Execute?new()("id")}`
- Jinja2 注入：`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

---

## 漏洞示例（禁止使用）

### FreeMarker 直接渲染用户输入的模板字符串（危险）

```java
// ❌ 危险：将用户输入作为模板字符串直接渲染
@PostMapping("/render")
public String renderTemplate(@RequestBody String templateContent) throws Exception {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
    Template template = new Template("dynamic", new StringReader(templateContent), cfg);
    StringWriter writer = new StringWriter();
    template.process(new HashMap<>(), writer);
    return writer.toString();
}
```

### Velocity 直接渲染用户输入的模板字符串（危险）

```java
// ❌ 危险：将用户输入作为 Velocity 模板字符串渲染
@PostMapping("/render")
public String renderTemplate(@RequestBody String templateContent) {
    VelocityContext context = new VelocityContext();
    StringWriter writer = new StringWriter();
    Velocity.evaluate(context, writer, "dynamic", templateContent);  // 攻击者可注入恶意模板语法
    return writer.toString();
}
```

### Jinja2 直接渲染用户输入的模板字符串（危险）

```python
# ❌ 危险：使用 render_template_string 渲染用户输入
from flask import render_template_string, request

@app.route('/render')
def render():
    template_content = request.args.get('template')
    return render_template_string(template_content)  # 攻击者可注入 {{config}} 等危险表达式
```

---

## 安全编码示例（推荐）

### 将用户输入作为数据传入模板，而非作为模板本身

最根本的防御方式：模板文件由开发者预先定义并存储在服务端，用户输入只能作为模板变量的值，**绝不能作为模板结构的一部分**。

```java
// ✅ 安全：模板文件预先定义，用户输入仅作为变量值
@PostMapping("/send-email")
public void sendEmail(@RequestBody EmailRequest request) throws Exception {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
    cfg.setClassForTemplateLoading(this.getClass(), "/templates");  // 从类路径加载预定义模板

    Template template = cfg.getTemplate("email-notification.ftl");  // 固定模板文件

    Map<String, Object> model = new HashMap<>();
    model.put("username", request.getUsername());    // 用户输入仅作为变量值
    model.put("message", request.getMessage());

    StringWriter writer = new StringWriter();
    template.process(model, writer);
}
```

```python
# ✅ 安全：使用预定义模板文件，用户输入仅作为变量
from flask import render_template, request

@app.route('/send-email', methods=['POST'])
def send_email():
    username = request.json.get('username')
    message = request.json.get('message')
    # render_template 加载预定义的模板文件，用户输入仅填充变量
    return render_template('email_notification.html', username=username, message=message)
```

### FreeMarker：配置安全策略，禁用危险特性

如果业务确实需要支持用户自定义模板，必须配置 FreeMarker 的安全策略，禁用危险的内置函数。

```java
// ✅ 安全：配置 FreeMarker 安全策略，禁用 new、api 等危险指令
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

// 禁用 ?new() 指令，防止实例化任意 Java 类
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

// 禁用 ?api 指令，防止访问底层 Java API
cfg.setAPIBuiltinEnabled(false);
```

### Jinja2：使用沙箱环境渲染用户模板

```python
# ✅ 安全：使用 jinja2.sandbox.SandboxedEnvironment 限制模板能力
from jinja2.sandbox import SandboxedEnvironment

SANDBOX_ENV = SandboxedEnvironment()

def render_user_template(template_string, context):
    # SandboxedEnvironment 限制了对危险属性和方法的访问
    template = SANDBOX_ENV.from_string(template_string)
    return template.render(**context)
```

### 对用户自定义模板内容进行严格校验

```java
// ✅ 安全：校验模板内容，拒绝包含危险关键字的模板
private static final List<String> DANGEROUS_KEYWORDS = List.of(
    "?new()", "?api", "Execute", "freemarker.template.utility",
    "Runtime", "ProcessBuilder", "ClassLoader"
);

public void validateTemplate(String templateContent) {
    for (String keyword : DANGEROUS_KEYWORDS) {
        if (templateContent.contains(keyword)) {
            throw new SecurityException("模板内容包含禁止使用的关键字: " + keyword);
        }
    }
}
```

---
