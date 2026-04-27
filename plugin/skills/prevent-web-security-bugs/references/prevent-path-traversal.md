# 防范路径遍历安全编码规范

## 什么是路径遍历

路径遍历（Path Traversal），又称目录遍历，是指攻击者通过在文件路径参数中注入 `../` 等特殊序列，使应用程序访问到预期目录之外的文件或目录，从而实现任意文件读取或任意文件写入。

- **任意文件读取**：读取服务器上的敏感文件，如 `/etc/passwd`、应用配置文件、私钥等。
- **任意文件写入**：将恶意内容写入服务器任意位置，如覆盖配置文件、写入 WebShell。

**典型攻击场景**：
- 文件下载接口：`/download?file=../../etc/passwd`
- 文件上传接口：上传文件名为 `../../webapps/ROOT/shell.jsp` 的文件
- 图片预览接口：`/preview?path=../../../etc/shadow`

---

## 漏洞示例（禁止使用）

### 直接拼接用户输入构造文件路径（危险）

```java
// ❌ 危险：直接拼接用户输入的文件名
@GetMapping("/download")
public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
    File file = new File("/app/uploads/" + filename);
    return ResponseEntity.ok(Files.readAllBytes(file.toPath()));
}
```

```python
# ❌ 危险：直接使用用户输入的路径读取文件
@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    file_path = os.path.join('/app/uploads', filename)
    with open(file_path, 'rb') as f:
        return f.read()
```

### 文件上传时信任客户端提供的文件名（危险）

```java
// ❌ 危险：直接使用上传文件的原始文件名保存
@PostMapping("/upload")
public void uploadFile(MultipartFile file) throws IOException {
    String filename = file.getOriginalFilename();  // 可能包含 ../
    File dest = new File("/app/uploads/" + filename);
    file.transferTo(dest);
}
```

---

## 安全编码示例（推荐）

### 使用规范化路径（Canonical Path）校验文件是否在允许目录内

将路径规范化后，校验其是否以允许的根目录为前缀，这是防止路径遍历最可靠的方式。

```java
// ✅ 安全：规范化路径后校验是否在允许目录内
@GetMapping("/download")
public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
    File baseDir = new File("/app/uploads").getCanonicalFile();
    File targetFile = new File(baseDir, filename).getCanonicalFile();

    if (!targetFile.getPath().startsWith(baseDir.getPath() + File.separator)) {
        throw new SecurityException("非法文件路径");
    }
    return ResponseEntity.ok(Files.readAllBytes(targetFile.toPath()));
}
```

```python
# ✅ 安全：使用 os.path.realpath 规范化后校验路径前缀
import os

BASE_DIR = os.path.realpath('/app/uploads')

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    target_path = os.path.realpath(os.path.join(BASE_DIR, filename))

    if not target_path.startswith(BASE_DIR + os.sep):
        raise ValueError("非法文件路径")

    with open(target_path, 'rb') as f:
        return f.read()
```

### 文件上传：服务端生成安全的文件名

上传文件时，**禁止使用客户端提供的原始文件名**，应由服务端生成随机文件名，仅保留经过校验的文件扩展名。

```java
// ✅ 安全：服务端生成随机文件名，仅保留白名单扩展名
private static final Set<String> ALLOWED_EXTENSIONS = Set.of("jpg", "jpeg", "png", "gif", "pdf");

@PostMapping("/upload")
public String uploadFile(MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    String extension = FilenameUtils.getExtension(originalFilename).toLowerCase();

    if (!ALLOWED_EXTENSIONS.contains(extension)) {
        throw new IllegalArgumentException("不允许的文件类型: " + extension);
    }

    String safeFilename = UUID.randomUUID() + "." + extension;
    File dest = new File("/app/uploads/" + safeFilename);
    file.transferTo(dest);
    return safeFilename;
}
```

```python
# ✅ 安全：服务端生成随机文件名，仅保留白名单扩展名
import uuid
import os

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}

@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']
    original_name = uploaded_file.filename
    extension = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(f"不允许的文件类型: {extension}")

    safe_filename = f"{uuid.uuid4()}.{extension}"
    uploaded_file.save(os.path.join('/app/uploads', safe_filename))
    return safe_filename
```

### 使用白名单限制可访问的文件

对于固定的文件集合（如静态资源、模板文件），使用白名单是最简单有效的防御方式。

```java
// ✅ 安全：白名单限制可下载的文件名
private static final Set<String> ALLOWED_FILES = Set.of("report.pdf", "manual.pdf", "terms.pdf");

@GetMapping("/download")
public ResponseEntity<byte[]> downloadFile(@RequestParam String filename) throws IOException {
    if (!ALLOWED_FILES.contains(filename)) {
        throw new SecurityException("不允许下载的文件: " + filename);
    }
    File file = new File("/app/static/" + filename);
    return ResponseEntity.ok(Files.readAllBytes(file.toPath()));
}
```

---
