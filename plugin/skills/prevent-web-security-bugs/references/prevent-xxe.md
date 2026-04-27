# 防范 XXE 安全编码规范

## 什么是 XXE

XXE（XML External Entity Injection，XML 外部实体注入）是指应用程序在解析 XML 输入时，未禁用外部实体（External Entity）功能，攻击者通过在 XML 中声明恶意的外部实体，使 XML 解析器加载并返回服务器本地文件内容，或向内网地址发起请求，从而实现任意文件读取、内网探测，甚至在某些解析器下执行系统命令。

**典型攻击场景**：
- 读取服务器本地文件：声明 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 并在 XML 中引用
- 内网服务探测：声明 `<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">` 探测内网端口
- 盲 XXE（Blind XXE）：通过带外通道（OOB）将文件内容外带至攻击者控制的服务器
- 拒绝服务（Billion Laughs）：通过嵌套实体引用耗尽解析器内存

**典型受影响场景**：
- 接收 XML 格式请求体的 REST/SOAP 接口
- 文件上传接口（上传 XML、SVG、DOCX、XLSX 等基于 XML 的文件格式）
- 使用 XML 配置文件且配置内容来自用户输入的场景

---

## 漏洞示例（禁止使用）

### 使用默认配置的 DocumentBuilder 解析用户输入（危险）

```java
// ❌ 危险：使用默认配置的 DocumentBuilder，未禁用外部实体
@PostMapping("/parse")
public String parseXml(@RequestBody String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();  // 默认配置允许外部实体
    Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
    return doc.getDocumentElement().getTextContent();
    // 攻击者可传入：
    // <?xml version="1.0"?>
    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    // <root>&xxe;</root>
}
```

### 使用默认配置的 SAXParser 解析用户输入（危险）

```java
// ❌ 危险：使用默认配置的 SAXParser，未禁用外部实体
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(new InputSource(new StringReader(userXmlInput)), handler);
```

### 使用默认配置的 XMLInputFactory 解析用户输入（危险）

```java
// ❌ 危险：使用默认配置的 StAX XMLInputFactory，未禁用外部实体
XMLInputFactory factory = XMLInputFactory.newInstance();
XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(userXmlInput));
```

### Python 使用 xml.etree.ElementTree 解析用户输入（危险）

```python
# ❌ 危险：Python 标准库 xml.etree.ElementTree 在某些版本下存在 XXE 风险
# 更安全的做法是使用 defusedxml 库
import xml.etree.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_content = request.data.decode('utf-8')
    root = ET.fromstring(xml_content)  # 存在 XXE 风险（取决于 Python 版本和底层 expat 配置）
    return root.find('name').text
```

---

## 安全编码示例（推荐）

### Java DOM 解析：禁用外部实体和 DOCTYPE 声明

防御 XXE 最可靠的方式是完全禁用 DOCTYPE 声明，或同时禁用外部通用实体和外部参数实体。

```java
// ✅ 安全：DocumentBuilder 禁用外部实体和 DOCTYPE
@PostMapping("/parse")
public String parseXml(@RequestBody String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    // 禁用外部通用实体
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    // 禁用外部参数实体
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    // 禁用外部 DTD 加载
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    // 完全禁用 DOCTYPE 声明（推荐，最彻底的防御）
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // 禁用 XInclude
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
    return doc.getDocumentElement().getTextContent();
}
```

### Java SAX 解析：禁用外部实体

```java
// ✅ 安全：SAXParser 禁用外部实体
public void safeParseWithSax(String xmlContent, DefaultHandler handler) throws Exception {
    SAXParserFactory factory = SAXParserFactory.newInstance();

    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    SAXParser parser = factory.newSAXParser();
    parser.parse(new InputSource(new StringReader(xmlContent)), handler);
}
```

### Java StAX 解析：禁用外部实体

```java
// ✅ 安全：XMLInputFactory 禁用外部实体支持
public XMLStreamReader safeCreateStreamReader(String xmlContent) throws XMLStreamException {
    XMLInputFactory factory = XMLInputFactory.newInstance();

    // 禁用外部实体支持
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
    // 禁用 DTD 支持
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);

    return factory.createXMLStreamReader(new StringReader(xmlContent));
}
```

### Java JAXB 解析：通过 SAXSource 包装安全的 SAXParser

```java
// ✅ 安全：JAXB 通过安全的 SAXSource 解析 XML，避免直接传入字符串
public <T> T safeUnmarshal(String xmlContent, Class<T> targetClass) throws Exception {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

    SAXParser saxParser = factory.newSAXParser();
    XMLReader xmlReader = saxParser.getXMLReader();

    JAXBContext context = JAXBContext.newInstance(targetClass);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    SAXSource source = new SAXSource(xmlReader, new InputSource(new StringReader(xmlContent)));
    return unmarshaller.unmarshal(source, targetClass).getValue();
}
```

### Python：使用 defusedxml 替代标准库

`defusedxml` 是专为防御 XML 攻击设计的库，默认禁用所有危险的 XML 特性，是 Python 中处理不可信 XML 的推荐方案。

```python
# ✅ 安全：使用 defusedxml 替代标准 xml 库
import defusedxml.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_content = request.data.decode('utf-8')
    # defusedxml 默认禁用外部实体、DTD 等危险特性
    root = ET.fromstring(xml_content)
    return root.find('name').text
```

```python
# ✅ 安全：defusedxml 同样提供 SAX、minidom 等安全替代
import defusedxml.sax
import defusedxml.minidom

# SAX 安全解析
defusedxml.sax.parseString(xml_bytes, handler)

# minidom 安全解析
doc = defusedxml.minidom.parseString(xml_bytes)
```

### 封装统一的安全 XML 解析工具方法

```java
// ✅ 安全：封装统一的安全 XML 解析工具，避免各处重复配置
public class SafeXmlParser {

    private static final DocumentBuilderFactory SAFE_FACTORY;

    static {
        SAFE_FACTORY = DocumentBuilderFactory.newInstance();
        try {
            SAFE_FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            SAFE_FACTORY.setFeature("http://xml.org/sax/features/external-general-entities", false);
            SAFE_FACTORY.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAFE_FACTORY.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            SAFE_FACTORY.setXIncludeAware(false);
            SAFE_FACTORY.setExpandEntityReferences(false);
        } catch (ParserConfigurationException e) {
            throw new ExceptionInInitializerError("无法初始化安全 XML 解析器: " + e.getMessage());
        }
    }

    public static Document parse(String xmlContent) throws Exception {
        DocumentBuilder builder = SAFE_FACTORY.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlContent)));
    }
}
```

---
