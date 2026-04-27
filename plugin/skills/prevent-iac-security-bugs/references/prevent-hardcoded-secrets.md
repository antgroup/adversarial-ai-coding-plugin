# 防范 IaC 配置文件中的凭据硬编码

## 目录

- [什么是 IaC 凭据硬编码](#什么是-iac-凭据硬编码)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)

---

## 什么是 IaC 凭据硬编码

将密码、API Key、Token、私钥、连接串等敏感信息以明文直接写入 Kubernetes YAML、Dockerfile、docker-compose、Terraform、Helm values 等配置文件。这类文件通常随代码一起提交到 Git 仓库，极易造成凭据泄露。

**典型攻击场景**：
- k8s ConfigMap 或 Deployment env 中明文存储数据库密码，YAML 被提交到 GitHub
- Dockerfile 中用 `ENV PASSWORD=xxx` 固化凭据，镜像层历史可直接提取
- Terraform 变量文件 `terraform.tfvars` 含云账号 AccessKey，被推入代码仓库
- docker-compose.yml 中 `MYSQL_ROOT_PASSWORD: 123456` 随项目公开

---

## 漏洞示例（禁止使用）

### Kubernetes Deployment 中明文 env（危险）

```yaml
# ❌ 危险：密码直接写在 env 中，YAML 提交后全员可见
spec:
  containers:
  - name: app
    env:
    - name: DB_PASSWORD
      value: "SuperSecret123"
    - name: API_KEY
      value: "sk-live-abc123def456"
```

### ConfigMap 存储敏感数据（危险）

```yaml
# ❌ 危险：ConfigMap 未加密，任何有 get configmap 权限的人都能读取
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_password: "Passw0rd@2024"
  redis_auth: "RedisSecret@123"
```

### Dockerfile 中硬编码凭据（危险）

```dockerfile
# ❌ 危险：即使后续层删除，历史层仍可提取
FROM ubuntu:22.04
ENV DB_PASSWORD=SuperSecret123
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
RUN apt-get update
```

### docker-compose 明文密码（危险）

```yaml
# ❌ 危险：明文密码提交到仓库
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword123
      MYSQL_PASSWORD: apppassword456
```

### Terraform 变量文件明文 AccessKey（危险）

```hcl
# ❌ 危险：terraform.tfvars 含真实凭据，不应提交
access_key = "LTAI5tXxxxxxxxxxxxx"
secret_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## 安全配置示例（推荐）

### 使用 Kubernetes Secret（基础方案）

```yaml
# ✅ 安全：通过 Secret 对象存储凭据（值需 base64 编码）
# 注意：Secret 默认只是 base64，需配合 etcd 加密和 RBAC 限制访问权限
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
stringData:                    # stringData 会自动 base64 编码
  db_password: ""              # 通过 CI/CD 注入，不硬编码真实值
  api_key: ""
---
# 在 Pod 中引用 Secret
spec:
  containers:
  - name: app
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secret
          key: db_password
    # 或挂载为文件（更安全，避免环境变量泄露）
    volumeMounts:
    - name: secret-vol
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secret-vol
    secret:
      secretName: app-secret
```

### 使用外部 Secret 管理（推荐生产方案）

```yaml
# ✅ 安全：使用 External Secrets Operator 从 Vault/KMS 动态拉取凭据
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend          # 指向已配置的 SecretStore
    kind: SecretStore
  target:
    name: app-secret             # 生成的 k8s Secret 名称
  data:
  - secretKey: db_password
    remoteRef:
      key: secret/app/database
      property: password
```

### docker-compose 使用环境变量文件

```yaml
# ✅ 安全：从 .env 文件读取，.env 加入 .gitignore
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}   # 从 .env 或环境注入
      MYSQL_PASSWORD: ${MYSQL_APP_PASSWORD}
```

```
# .gitignore
.env
.env.local
*.tfvars
!terraform.tfvars.example    # 仅提交不含真实值的示例
```

### Dockerfile 构建时凭据处理

```dockerfile
# ✅ 安全：使用 BuildKit secret 挂载，不写入镜像层
# syntax=docker/dockerfile:1
FROM ubuntu:22.04
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install
# 构建命令：docker build --secret id=npm_token,src=.npm_token .
```

### Terraform 凭据管理

```hcl
# ✅ 安全：从环境变量读取，或使用 Vault Provider
provider "aws" {
  # 从环境变量 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY 读取
  # 或使用 IAM Role（推荐）
}

# 推荐：使用 Vault Provider 动态获取短期凭据
data "vault_aws_access_credentials" "creds" {
  backend = "aws"
  role    = "deploy-role"
}
```

---

## 核心原则

- **零明文提交**：凭据类信息永远不进入 Git 历史，`.gitignore` 排除所有 `.env`、`*.tfvars`、`secrets/` 目录
- **Secret vs ConfigMap**：密码、Token、Key 用 Secret；非敏感配置才用 ConfigMap
- **外部托管优先**：生产环境使用 External Secrets + Vault/KMS，而非直接在 Secret YAML 中写值
- **镜像层不留凭据**：Dockerfile 中避免 `ENV` 设置凭据，构建期临时凭据用 `--mount=type=secret`
- **RBAC 最小化**：限制 `get secret` 权限，普通业务账号不应能读取所有 Secret
