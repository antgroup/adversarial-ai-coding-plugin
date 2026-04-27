# 防范硬编码凭证安全编码规范

## 什么是硬编码凭证漏洞

硬编码凭证（Hardcoded Credentials / Secrets）是指将 API Key、密码、数据库连接字符串、私钥、Token 等敏感信息直接写入源代码中。这类代码一旦提交到版本控制系统（Git），即使后续删除，历史记录中仍然保留，任何有仓库访问权限的人（包括泄露的公开仓库读者）都可提取这些凭证，造成账号被盗、数据泄露、云资源滥用等严重后果。

**典型攻击场景 —— GitHub 公开仓库泄露**

```
开发者将包含 AWS_SECRET_KEY 的代码推送到 GitHub，
攻击者通过自动化扫描工具（truffleHog、gitleaks）在数分钟内发现，
使用该密钥创建大量云实例用于挖矿，产生数万美元账单。
```

## 漏洞示例（禁止使用）

### 示例1（危险）：API Key 直接写在代码中

```typescript
// 危险：密钥硬编码，所有能读代码的人都能看到
const gcpApiKey = 'AIzaSyD-9tSrke72I6e64H4VsZx7k4n3EXAMPLE';
const client = new GoogleMapsClient({ key: gcpApiKey });
```

### 示例2（危险）：数据库密码硬编码

```typescript
// 危险：生产数据库凭证写在源码里
const pool = mysql.createPool({
  host: 'prod-db.example.com',
  user: 'admin',
  password: 'Sup3rS3cr3tP@ssw0rd!', // 高危
  database: 'customers',
});
```

### 示例3（危险）：JWT 密钥硬编码

```typescript
// 危险：任何人拿到代码都可以伪造任意用户的 token
const JWT_SECRET = 'my-super-secret-key-12345';
const token = jwt.sign({ userId }, JWT_SECRET);
```

### 示例4（危险）：凭证混入配置对象

```typescript
// 危险：即使放在配置文件里，只要该文件被提交到 Git 就不安全
export const config = {
  stripe: {
    secretKey: 'sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX', // 高危
  },
  sendgrid: {
    apiKey: 'SG.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', // 高危
  },
};
```

## 安全编码示例（推荐）

### 示例1：通过环境变量读取敏感配置

```typescript
// 安全：运行时从环境变量读取，不写入代码
const gcpApiKey = process.env.GCP_API_KEY;
if (!gcpApiKey) {
  throw new Error('环境变量 GCP_API_KEY 未配置');
}
const client = new GoogleMapsClient({ key: gcpApiKey });
```

### 示例2：使用 dotenv 管理本地开发环境变量（.env 不提交 Git）

```typescript
// .env 文件（必须加入 .gitignore）
// GCP_API_KEY=AIzaSyD-...
// DB_PASSWORD=...

// 代码中加载
import 'dotenv/config'; // 只在开发环境使用

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // 从环境变量读取
  database: process.env.DB_NAME,
});
```

## 敏感信息识别清单

以下信息**不得**出现在源代码或配置文件（如被 Git 追踪）中：

| 类型 | 示例模式 |
|------|----------|
| AWS 凭证 | `AKIA...`（Access Key ID）、任何 Secret Access Key |
| GCP API Key | `AIzaSy...` |
| GitHub Token | `ghp_...`、`ghs_...` |
| Stripe Key | `sk_live_...`、`pk_live_...` |
| JWT Secret | 任何用于签名的固定字符串 |
| 数据库密码 | 连接字符串中的 password 字段 |
| 私钥文件 | `-----BEGIN RSA PRIVATE KEY-----` |
| SendGrid/Twilio | `SG.`、`AC...`/`SK...` |

## 核心原则总结

- **凭证不入代码**：所有密钥、密码、token 必须通过环境变量或密钥管理服务注入，不得硬编码在任何被 Git 追踪的文件中
- **.env 文件加入 .gitignore**：本地开发的 .env 文件只在本机存在，绝对不提交
- **密钥轮换机制**：一旦发现密钥可能泄露（如错误提交），立即在服务商处吊销并重新生成，不要仅依赖 Git 历史清除
- **CI/CD 集成扫描**：在代码提交前通过 gitleaks、truffleHog 等工具自动扫描，阻断泄露
- **生产环境用密钥管理服务**：阿里云凭据管家、腾讯云凭据管理系统（SSM），避免依赖运维人员手动管理环境变量
