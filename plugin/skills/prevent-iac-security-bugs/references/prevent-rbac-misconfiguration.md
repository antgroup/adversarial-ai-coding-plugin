# 防范 RBAC 过度授权与错误配置

## 目录

- [什么是 RBAC 过度授权](#什么是-rbac-过度授权)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)
- [合理例外](#合理例外)

---

## 什么是 RBAC 过度授权

Kubernetes RBAC（Role-Based Access Control）过度授权是指 ServiceAccount 或用户账号被赋予了超出业务实际需要的权限，包括通配符权限、cluster-admin 滥用、默认 ServiceAccount 挂载，以及对 Secret 的过度读取权限。

**典型攻击场景**：
- 应用 Pod 使用默认 ServiceAccount，攻击者在 Pod 内调用 k8s API 获取所有 Secret
- 误用 `cluster-admin` 角色，单个账号被攻破即导致整集群沦陷
- `verbs: ["*"]` + `resources: ["*"]` 的通配符规则，相当于无访问控制
- RBAC 允许创建 Pod，攻击者用特权 Pod 逃逸宿主机

---

## 漏洞示例（禁止使用）

### 通配符权限（危险）

```yaml
# ❌ 危险：通配符赋予对所有资源的所有操作权限
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: over-privileged-role
rules:
- apiGroups: ["*"]       # 所有 API 组
  resources: ["*"]       # 所有资源
  verbs: ["*"]           # 所有操作
```

### 直接绑定 cluster-admin（危险）

```yaml
# ❌ 危险：将 cluster-admin 绑定到业务 ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin-binding
subjects:
- kind: ServiceAccount
  name: default           # 默认 ServiceAccount，影响命名空间内所有 Pod
  namespace: production
roleRef:
  kind: ClusterRole
  name: cluster-admin     # 集群最高权限
  apiGroup: rbac.authorization.k8s.io
```

### Pod 挂载默认 ServiceAccount（危险）

```yaml
# ❌ 危险：未禁用 automountServiceAccountToken，默认挂载可访问 k8s API 的 token
spec:
  containers:
  - name: app
    image: myapp:1.0
  # 默认 automountServiceAccountToken: true，token 挂载在 /var/run/secrets/kubernetes.io/serviceaccount/
```

### Role 允许操作 Secret（危险）

```yaml
# ❌ 危险：允许 list/get secret，攻击者可读取命名空间内所有凭据
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]   # list 可枚举所有 secret 名称
```

### 授予 impersonate 权限（危险）

```yaml
# ❌ 危险：impersonate 允许账号模拟任意用户/ServiceAccount，继承其全部权限
# 相当于间接获得 cluster-admin（若被模拟对象拥有高权限）
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]            # 高危：可绕过所有基于身份的权限控制
```

---

## 安全配置示例（推荐）

### 最小权限 ServiceAccount

```yaml
# ✅ 安全：为应用创建专用 ServiceAccount，只赋予必要权限
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
automountServiceAccountToken: false   # 默认不挂载，只在需要时显式启用
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]                       # 只允许读取 ConfigMap，精确到动词
  resourceNames: ["app-config"]        # 只允许访问特定名称的资源
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-role-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-service-account
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### 需要 k8s API 访问时显式启用并限制权限

```yaml
# ✅ 安全：需要访问 k8s API 时，显式挂载 token 并精确限权
spec:
  serviceAccountName: app-service-account
  automountServiceAccountToken: true    # 显式启用（业务确实需要时）
  containers:
  - name: app
    image: myapp:1.0
```

### 禁用默认 ServiceAccount 的 API 访问

```yaml
# ✅ 安全：修补默认 ServiceAccount，禁止自动挂载
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: production
automountServiceAccountToken: false   # 禁止默认 ServiceAccount 挂载 token
```

### 对 Secret 的精细化访问控制

```yaml
# ✅ 安全：只授予对特定 Secret 的 get 权限，禁止 list/watch（防止枚举）
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]                        # 不授予 list，防止枚举所有 Secret 名称
  resourceNames: ["app-db-secret"]      # 只允许访问该 Pod 需要的特定 Secret
```

### 审计现有 RBAC 权限

```bash
# 查看某 ServiceAccount 的有效权限
kubectl auth can-i --list --as=system:serviceaccount:production:app-service-account

# 查找所有绑定了 cluster-admin 的账号（应定期执行）
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
```

---

## 核心原则

- **最小权限**：每个 ServiceAccount 只授予完成业务所需的最少 verbs 和 resources
- **命名空间隔离**：优先用 Role + RoleBinding（命名空间级别），避免 ClusterRole
- **禁止通配符**：apiGroups、resources、verbs 都不使用 `"*"`，精确枚举
- **默认禁用挂载**：`automountServiceAccountToken: false` 作为基线，需要时才显式启用
- **不授予 list secret**：`list`/`watch` Secret 可枚举所有凭据，按需只授予 `get` + `resourceNames`
- **禁止创建 Pod/Exec**：RBAC 中 `pods/exec`、`pods/create` 权限可用于逃逸，须严格控制
- **禁止 impersonate 权限**：`impersonate` 动词允许账号模拟任意用户或 ServiceAccount，相当于继承其全部权限；若被模拟对象拥有高权限，可间接绕过所有基于身份的访问控制，不应出现在任何业务角色中

## 合理例外

### Operator / Controller 必须挂载 SA Token

ArgoCD、Flux、Prometheus Operator、自定义 Controller 等遵循 [Operator 模式](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) 的组件，需要持续 watch/list/update k8s 资源，`automountServiceAccountToken: true` 是其正常工作的前提。这不是过度授权，而是 controller 模式的基本运作方式。

```yaml
# ✅ 合理：Operator 显式启用 SA Token，并精确限定权限范围
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-operator
  namespace: operators
automountServiceAccountToken: true    # Operator 需要，显式声明
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-operator-role
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]  # 精确到业务需要的动词
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update"]
# 注意：即使是 Operator，也不应授予 secrets list/watch 或 pods/exec
```

**判断原则**：
- 挂载 SA Token 本身不是风险，**Token 拥有的权限范围**才是核心
- Operator 的 ClusterRole 应精确列出 verbs 和 resources，不使用通配符
- 定期用 `kubectl auth can-i --list` 审计实际权限，确保未产生权限漂移
- CI/CD 系统（Tekton、Argo Workflows）中创建 Pod 是合理需求，但应限定在专用命名空间，配合 ResourceQuota 防止滥用
