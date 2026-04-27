# 防范反序列化安全编码规范

## 什么是反序列化漏洞

反序列化漏洞（Insecure Deserialization）是指应用程序在将不可信的字节流或 JSON/XML 数据还原为对象时，攻击者通过构造恶意的序列化数据，触发目标类的特殊方法（如 `readObject`、`finalize`）或利用反射机制，在服务端执行任意代码、篡改应用逻辑或绕过身份认证。

常见的反序列化场景包括：

- **Java 原生反序列化**：使用 `ObjectInputStream.readObject()` 反序列化字节流
- **JSON 反序列化**：使用 Jackson、Gson、Fastjson 等框架解析 JSON 字符串时启用了多态类型支持
- **XML 反序列化**：使用 XStream 等框架将 XML 还原为 Java 对象

**典型攻击场景**：
- Cookie 或 Session 中存储了序列化对象，攻击者篡改后提交触发 RCE
- 接口接收 Base64 编码的序列化数据，攻击者替换为包含恶意 gadget chain 的 payload
- Jackson 开启 `enableDefaultTyping` 后，攻击者传入 `["com.sun.rowset.JdbcRowSetImpl", {...}]` 触发 JNDI 注入

---

## 漏洞示例（禁止使用）

### Java 原生反序列化直接处理用户输入（危险）

```java
// ❌ 危险：直接对用户提交的字节流进行反序列化
@PostMapping("/deserialize")
public Object deserialize(@RequestBody byte[] data) throws IOException, ClassNotFoundException {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);
    return ois.readObject();  // 攻击者可提交包含恶意 gadget chain 的序列化数据
}
```

```java
// ❌ 危险：从 Cookie 中读取 Base64 编码的序列化对象并直接反序列化
String cookieValue = request.getCookies()[0].getValue();
byte[] data = Base64.getDecoder().decode(cookieValue);
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object obj = ois.readObject();  // Cookie 可被攻击者篡改
```

### Jackson 开启多态类型支持（危险）

```java
// ❌ 危险：开启 enableDefaultTyping，允许 JSON 中指定任意类名
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 已废弃，但仍被大量旧代码使用，极度危险
Object obj = mapper.readValue(userInputJson, Object.class);
```

```java
// ❌ 危险：使用 @JsonTypeInfo 配合 Object 类型字段，允许客户端控制具体类型
public class Request {
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)  // 允许 JSON 中通过 @class 指定任意类
    private Object data;
}
```

### Fastjson 开启 AutoType（危险）

```java
// ❌ 危险：开启 autoType 支持，允许 JSON 中通过 @type 字段指定任意类
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
Object obj = JSON.parseObject(userInputJson);  // 攻击者可通过 @type 触发任意类实例化
```

### XStream 未配置安全策略（危险）

```java
// ❌ 危险：使用默认配置的 XStream 反序列化用户输入的 XML
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInputXml);  // 攻击者可通过构造恶意 XML 执行任意代码
```

---

## 安全编码示例（推荐）

### Java 原生反序列化：使用白名单过滤器限制可反序列化的类

如果业务确实需要使用 Java 原生反序列化，必须通过 `ObjectInputFilter` 限制允许反序列化的类，拒绝所有不在白名单中的类。

```java
// ✅ 安全：使用 ObjectInputFilter 白名单限制可反序列化的类（Java 9+）
@PostMapping("/deserialize")
public Object deserialize(@RequestBody byte[] data) throws IOException, ClassNotFoundException {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);

    // 仅允许反序列化白名单中的类
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
        "com.example.model.SafeData;com.example.model.UserProfile;!*"
    );
    ois.setObjectInputFilter(filter);

    return ois.readObject();
}
```

```java
// ✅ 安全：使用 Apache Commons IO 提供的 ValidatingObjectInputStream（Java 8 兼容）
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public Object safeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ValidatingObjectInputStream vois = new ValidatingObjectInputStream(bis);

    // 只接受白名单中的类
    vois.accept(SafeData.class, UserProfile.class);
    // 拒绝所有其他类
    vois.reject("*");

    return vois.readObject();
}
```

### Jackson：禁用多态类型支持，使用明确的目标类型

```java
// ✅ 安全：不开启 defaultTyping，反序列化时指定明确的目标类型
ObjectMapper mapper = new ObjectMapper();
// 不调用 enableDefaultTyping()，不使用 @JsonTypeInfo(use = Id.CLASS)

// 反序列化时指定具体类型，而非 Object.class
UserRequest request = mapper.readValue(userInputJson, UserRequest.class);
```

```java
// ✅ 安全：如果确实需要多态支持，使用 @JsonTypeInfo 配合命名类型（而非类名）
// 在父类上声明，通过逻辑名称而非全限定类名区分子类型
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = CircleShape.class, name = "circle"),
    @JsonSubTypes.Type(value = RectShape.class, name = "rect")
})
public abstract class Shape { }
// 攻击者无法通过 type 字段指定任意类，只能使用预定义的 "circle" 或 "rect"
```

### Fastjson：不开启 AutoType，使用明确的目标类型

```java
// ✅ 安全：不开启 autoType，反序列化时指定明确的目标类型
// 不调用 ParserConfig.getGlobalInstance().setAutoTypeSupport(true)
UserRequest request = JSON.parseObject(userInputJson, UserRequest.class);
```

```java
// ✅ 安全：如果必须使用 autoType，配置类白名单而非全局开启
ParserConfig config = new ParserConfig();
config.addAccept("com.example.model.");  // 仅允许指定包下的类
Object obj = JSON.parseObject(userInputJson, Object.class, config);
```

### XStream：配置安全白名单，禁止反序列化任意类

```java
// ✅ 安全：配置 XStream 安全策略，仅允许白名单中的类
XStream xstream = new XStream();

// 清除默认权限，拒绝所有类
xstream.addPermission(NoTypePermission.NONE);

// 仅允许白名单中的类和包
xstream.addPermission(new ExplicitTypePermission(new Class[]{UserProfile.class, OrderInfo.class}));
xstream.allowTypesByWildcard(new String[]{"com.example.model.**"});

Object obj = xstream.fromXML(userInputXml);
```

### 通用原则：避免在接口中直接接收序列化数据

```java
// ✅ 安全：使用结构化的 JSON/DTO 替代原生序列化数据传输
// 不要让接口直接接收 byte[] 序列化数据，改为接收明确结构的 DTO
@PostMapping("/process")
public ResponseEntity<Void> processRequest(@RequestBody @Valid UserRequest request) {
    // request 是明确类型的 DTO，Jackson 按字段映射，不涉及任意类实例化
    userService.process(request);
    return ResponseEntity.ok().build();
}
```

```python
# ✅ 安全：Python 中避免使用 pickle 反序列化用户输入，改用 JSON
import json

# ❌ 危险写法（不要这样做）：
# import pickle
# obj = pickle.loads(user_provided_bytes)  # pickle 可执行任意代码

# ✅ 安全：使用 json.loads 并指定明确的数据结构
def process_request(raw_json: str) -> dict:
    data = json.loads(raw_json)
    # 对解析结果进行类型和字段校验
    if not isinstance(data.get('user_id'), int):
        raise ValueError("user_id 必须为整数")
    return data
```

---
