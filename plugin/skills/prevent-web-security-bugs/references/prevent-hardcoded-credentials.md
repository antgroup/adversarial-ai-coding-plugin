# 防范凭据硬编码安全编码规范

## 什么是凭据硬编码

凭据硬编码（Hardcoded Credentials）是指将密码、API 密钥、数据库连接串、加密密钥、Token 等敏感信息以明文形式直接写入源代码或配置文件中。一旦代码仓库泄露（如 GitHub 公开仓库、内部代码库权限失控），攻击者即可直接获取这些凭据，进而入侵数据库、云服务或第三方平台。

**典型攻击场景**：
- 开发者将含有数据库密码的代码提交至公开 GitHub 仓库，攻击者通过 GitHub 搜索直接获取凭据
- 应用程序 JAR 包被反编译，攻击者从 class 文件中提取硬编码的 API 密钥
- 配置文件随 Docker 镜像一起发布，镜像中包含明文的云服务 AccessKey
- 离职员工利用曾经看到的硬编码凭据访问生产系统

---

## 漏洞示例（禁止使用）

### 数据库密码硬编码（危险）

```java
// ❌ 危险：数据库连接凭据直接硬编码在代码中
public DataSource createDataSource() {
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl("jdbc:mysql://prod-db.example.com:3306/myapp");
    config.setUsername("root");
    config.setPassword("Passw0rd@2024");  // 硬编码密码
    return new HikariDataSource(config);
}
```

```python
# ❌ 危险：数据库连接字符串硬编码
DATABASE_URL = "postgresql://admin:SuperSecret123@prod-db.example.com:5432/myapp"
engine = create_engine(DATABASE_URL)
```

### API 密钥和 Token 硬编码（危险）

```java
// ❌ 危险：第三方服务 API 密钥硬编码
public class SmsService {
    private static final String API_KEY = "sk-live-abc123def456ghi789";  // 硬编码 API 密钥
    private static final String API_SECRET = "your-secret-key-here";

    public void sendSms(String phone, String message) {
        // 使用硬编码的密钥调用短信服务
    }
}
```

```python
# ❌ 危险：云服务 AccessKey 硬编码
import oss2

ACCESS_KEY_ID = "LTAI5tXxxxxxxxxxxxx"       # 硬编码 AccessKey ID
ACCESS_KEY_SECRET = "xxxxxxxxxxxxxxxxxxxxxxxx"  # 硬编码 AccessKey Secret

auth = oss2.Auth(ACCESS_KEY_ID, ACCESS_KEY_SECRET)
```

### 加密密钥硬编码（危险）

```java
// ❌ 危险：AES 加密密钥硬编码
public class EncryptionUtil {
    private static final String SECRET_KEY = "MyHardcodedKey12";  // 硬编码加密密钥
    private static final String IV = "InitializationVe";

    public static byte[] encrypt(String plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        // ...
    }
}
```

### 配置文件中明文存储凭据（危险）

```yaml
# ❌ 危险：application.yml 中明文写入数据库密码
spring:
  datasource:
    url: jdbc:mysql://prod-db.example.com:3306/myapp
    username: root
    password: Passw0rd@2024  # 明文密码提交到代码仓库
```

```properties
# ❌ 危险：application.properties 中明文写入 Redis 密码
redis.host=prod-redis.example.com
redis.port=6379
redis.password=RedisSecret@123
```

---

## 安全编码示例（推荐）

### 使用配置中心或密钥管理服务（KMS/Secret Manager）

对于生产环境，推荐使用专用密钥管理服务，实现凭据的集中管理、自动轮转和审计。

#### 使用环境变量（通用方案）

最简单且可移植的方案：所有凭据通过环境变量注入，代码中不出现任何明文。

```java
// ✅ 安全：从环境变量读取数据库凭据
@Component
public class DatabaseConfig {

    public DataSource createDataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(System.getenv("DB_URL"));
        config.setUsername(System.getenv("DB_USERNAME"));
        config.setPassword(System.getenv("DB_PASSWORD"));
        return new HikariDataSource(config);
    }
}
```

```python
# ✅ 安全：从环境变量读取凭据
import os
from sqlalchemy import create_engine

db_url = os.environ["DATABASE_URL"]  # 启动时若未设置则抛出 KeyError，明确失败
engine = create_engine(db_url)
```

#### 使用阿里云凭据管家（Secrets Manager）

适用于部署在阿里云的应用。ECS 实例绑定 RAM 角色后，SDK 自动获取临时凭证，代码中无需硬编码任何 AccessKey。

> 官方文档：[凭据管家快速入门](https://help.aliyun.com/zh/kms/secrets-manager/getting-started/)

```java
// Maven 依赖：com.aliyun:alibabacloud-kms20160120:2.1.0
import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GetSecretValueRequest;
import com.aliyun.kms20160120.models.GetSecretValueResponse;
import com.aliyun.teaopenapi.models.Config;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class DatabaseConfig {

    public DataSource createDataSource() throws Exception {
        // ECS 绑定 RAM 角色后，SDK 自动通过元数据服务获取临时凭证，无需硬编码 AK
        Config config = new Config()
            .setEndpoint("kms.cn-hangzhou.aliyuncs.com");
        Client kmsClient = new Client(config);

        GetSecretValueResponse resp = kmsClient.getSecretValue(
            new GetSecretValueRequest().setSecretName("prod/myapp/database")
        );

        // 凭据以 JSON 字符串存储：{"username":"...","password":"..."}
        ObjectMapper mapper = new ObjectMapper();
        JsonNode secret = mapper.readTree(resp.getBody().getSecretData());

        HikariConfig hikari = new HikariConfig();
        hikari.setJdbcUrl("jdbc:mysql://prod-db.example.com:3306/myapp");
        hikari.setUsername(secret.get("username").asText());
        hikari.setPassword(secret.get("password").asText());
        return new HikariDataSource(hikari);
    }
}
```

```python
# pip install alibabacloud-kms20160120
import json
from alibabacloud_kms20160120.client import Client
from alibabacloud_kms20160120.models import GetSecretValueRequest
from alibabacloud_tea_openapi.models import Config

def get_database_credentials() -> dict:
    # ECS 绑定 RAM 角色后，SDK 自动获取临时凭证，无需在代码中填写 AK
    config = Config(endpoint="kms.cn-hangzhou.aliyuncs.com")
    client = Client(config)

    request = GetSecretValueRequest(secret_name="prod/myapp/database")
    response = client.get_secret_value(request)
    return json.loads(response.body.secret_data)

credentials = get_database_credentials()
engine = create_engine(
    f"postgresql://{credentials['username']}:{credentials['password']}@prod-db.example.com:5432/myapp"
)
```

#### 使用腾讯云凭据管理系统（SSM）

适用于部署在腾讯云的应用。CVM 实例绑定 CAM 角色后，SDK 通过元数据服务自动获取临时凭证，代码中无需硬编码 SecretId/SecretKey。

> 官方文档：[凭据管理系统快速入门](https://cloud.tencent.com/document/product/1140/40869)

```java
// Maven 依赖：com.tencentcloudapi:tencentcloud-sdk-java:3.x.x
import com.tencentcloudapi.common.Credential;
import com.tencentcloudapi.common.provider.CvmRoleCredential;
import com.tencentcloudapi.ssm.v20190923.SsmClient;
import com.tencentcloudapi.ssm.v20190923.models.GetSecretValueRequest;
import com.tencentcloudapi.ssm.v20190923.models.GetSecretValueResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class DatabaseConfig {

    public DataSource createDataSource() throws Exception {
        // CVM 绑定 CAM 角色后自动获取临时凭证，无需硬编码 SecretId/SecretKey
        Credential cred = new CvmRoleCredential();
        SsmClient client = new SsmClient(cred, "ap-guangzhou");

        GetSecretValueRequest req = new GetSecretValueRequest();
        req.setSecretName("prod/myapp/database");
        GetSecretValueResponse resp = client.GetSecretValue(req);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode secret = mapper.readTree(resp.getSecretString());

        HikariConfig hikari = new HikariConfig();
        hikari.setJdbcUrl("jdbc:mysql://prod-db.example.com:3306/myapp");
        hikari.setUsername(secret.get("username").asText());
        hikari.setPassword(secret.get("password").asText());
        return new HikariDataSource(hikari);
    }
}
```

```python
# pip install tencentcloud-sdk-python
import json
from tencentcloud.common.credential import CvmRoleCredential
from tencentcloud.ssm.v20190923 import ssm_client, models

def get_database_credentials() -> dict:
    # CVM 绑定 CAM 角色后自动获取临时凭证，无需硬编码密钥
    cred = CvmRoleCredential()
    client = ssm_client.SsmClient(cred, "ap-guangzhou")

    req = models.GetSecretValueRequest()
    req.SecretName = "prod/myapp/database"
    resp = client.GetSecretValue(req)
    return json.loads(resp.SecretString)

credentials = get_database_credentials()
engine = create_engine(
    f"postgresql://{credentials['username']}:{credentials['password']}@prod-db.example.com:5432/myapp"
)


### 通用原则：防止凭据意外提交到代码仓库

```
# ✅ 安全：在项目根目录维护 .gitignore，排除所有可能包含凭据的文件
.env
.env.*
!.env.example       # 仅提交不含真实值的示例文件
secrets/
*.pem
*.key
*.p12
*.jks
```
---
