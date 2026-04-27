# 防范 SSRF 安全编码规范

## 什么是 SSRF

SSRF（Server-Side Request Forgery，服务端请求伪造）是指攻击者通过控制服务端发起的网络请求的目标地址，使服务器向攻击者指定的内网地址或外部地址发送请求，从而探测内网服务、绕过防火墙、读取云服务元数据，甚至进一步攻击内网系统。

**典型攻击场景**：
- 读取云服务器元数据：`http://169.254.169.254/latest/meta-data/`
- 探测内网服务：`http://192.168.1.1:8080/admin`
- 访问本地服务：`http://localhost:6379`（Redis 未授权访问）

---

## 漏洞示例（禁止使用）

### 直接使用用户输入的 URL 发起请求（危险）

```java
// ❌ 危险：直接使用用户传入的 URL 发起 HTTP 请求
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws IOException {
    URL targetUrl = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
    return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
}
```

```python
# ❌ 危险：直接使用用户传入的 URL 发起请求
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
```

### 仅校验 URL 前缀（危险）

```java
// ❌ 危险：仅校验前缀，攻击者可用 http://trusted.com.evil.com 绕过
if (!url.startsWith("https://trusted.com")) {
    throw new IllegalArgumentException("非法 URL");
}
```

---

## 安全编码示例（推荐）

### 使用白名单限制请求目标域名

对于业务上只需要访问固定域名的场景，使用白名单是最安全的防御方式。

```java
// ✅ 安全：白名单校验目标域名
private static final Set<String> ALLOWED_HOSTS = Set.of("api.trusted.com", "cdn.example.com");

public String fetchUrl(String urlString) throws IOException {
    URL url = new URL(urlString);
    String host = url.getHost();
    if (!ALLOWED_HOSTS.contains(host)) {
        throw new SecurityException("不允许访问的目标地址: " + host);
    }
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
}
```

```python
# ✅ 安全：白名单校验目标域名
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.trusted.com", "cdn.example.com"}

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"不允许访问的目标地址: {parsed.hostname}")
    response = requests.get(url, timeout=5)
    return response.text
```

### 解析 IP 后校验是否为内网地址

对于需要访问用户指定 URL 的场景，必须在 DNS 解析后校验目标 IP，防止通过内网域名绕过。

```python
# ✅ 安全：解析 IP 后校验是否为私有地址
import ipaddress
import socket
from urllib.parse import urlparse

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True  # 解析失败视为不安全

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("仅允许 HTTP/HTTPS 协议")
    if is_private_ip(parsed.hostname):
        raise ValueError("禁止访问内网地址")
    response = requests.get(url, timeout=5, allow_redirects=False)
    return response.text
```

```java
// ✅ 安全：解析 IP 后校验是否为私有地址
public boolean isPrivateAddress(String host) throws UnknownHostException {
    InetAddress address = InetAddress.getByName(host);
    return address.isLoopbackAddress()
        || address.isSiteLocalAddress()
        || address.isLinkLocalAddress()
        || address.isAnyLocalAddress();
}

public String safeFetch(String urlString) throws IOException {
    URL url = new URL(urlString);
    if (!url.getProtocol().matches("https?")) {
        throw new SecurityException("仅允许 HTTP/HTTPS 协议");
    }
    if (isPrivateAddress(url.getHost())) {
        throw new SecurityException("禁止访问内网地址");
    }
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setInstanceFollowRedirects(false);  // 禁止自动跟随重定向
    return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
}
```

### 禁止跟随重定向

重定向可能将请求从合法外网地址引导至内网地址，必须禁用自动重定向或对重定向目标再次校验。

```python
# ✅ 安全：禁止自动跟随重定向
response = requests.get(url, allow_redirects=False, timeout=5)
if response.status_code in (301, 302, 303, 307, 308):
    raise ValueError("禁止跟随重定向")
```

---
