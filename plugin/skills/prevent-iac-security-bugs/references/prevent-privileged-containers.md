# 防范特权容器与 root 运行安全规范

## 目录

- [什么是特权容器风险](#什么是特权容器风险)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)
- [合理例外](#合理例外)

---

## 什么是特权容器风险

以 root 用户或特权模式运行容器，意味着容器内进程拥有与宿主机 root 相当的权限。一旦容器被攻破，攻击者可轻易逃逸到宿主机，进而横向移动至整个集群。

**典型攻击场景**：
- 容器以 `privileged: true` 运行，攻击者通过挂载宿主机设备逃逸
- 容器以 root（UID 0）运行，文件系统漏洞可直接写入宿主机路径
- `allowPrivilegeEscalation: true` 允许子进程提权，配合内核漏洞完成逃逸

---

## 漏洞示例（禁止使用）

### 特权模式（危险）

```yaml
# ❌ 危险：privileged 模式赋予容器几乎所有内核能力
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      privileged: true
```

### 以 root 运行且允许提权（危险）

```yaml
# ❌ 危险：未设置 runAsNonRoot，容器默认以镜像定义的用户（通常是 root）运行
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: true   # 允许子进程通过 setuid 提权
```

### Pod 级别缺少安全上下文（危险）

```yaml
# ❌ 危险：整个 Pod 没有 securityContext，所有容器默认继承不安全配置
spec:
  containers:
  - name: app
    image: myapp:1.0
    # 无 securityContext
```

---

## 安全配置示例（推荐）

### 最小权限 securityContext

```yaml
# ✅ 安全：明确禁止特权，强制非 root，禁止提权
spec:
  securityContext:
    runAsNonRoot: true          # Pod 级别：所有容器必须以非 root 运行
    runAsUser: 1000             # 指定非特权 UID
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault      # 启用默认 seccomp 过滤
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false   # 禁止提权
      privileged: false                 # 禁止特权模式
      readOnlyRootFilesystem: true      # 根文件系统只读，限制攻击者写入
      capabilities:
        drop:
          - ALL                         # 丢弃所有 Linux Capabilities
        add:
          - NET_BIND_SERVICE            # 仅按需添加必要 Capability
```

### Dockerfile 层面固化非 root 用户

```dockerfile
# ✅ 安全：在镜像中创建专用非特权用户
FROM node:18-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser   # 切换到非 root 用户，k8s 启动时无需额外配置
```

### PodSecurityAdmission（集群级别强制）

```yaml
# ✅ 安全：命名空间级别强制执行 restricted 策略
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted     # 强制执行
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

---

## 核心原则

- **最小权限**：容器只申请完成任务所需的最低权限，其余一律 drop
- **非 root 强制**：在 Pod 级别设置 `runAsNonRoot: true`，镜像层面固化 USER 指令
- **只读根文件系统**：`readOnlyRootFilesystem: true` + 单独挂载可写目录（如 `/tmp`）
- **禁止提权**：`allowPrivilegeEscalation: false` 是基线要求，无例外

## 合理例外

以下平台级组件需要 `privileged: true` 或 root 运行，属于合理的基础设施需求，不应与业务容器使用相同策略：

| 组件类型 | 代表工具 | 需要特权的原因 |
|---|---|---|
| CNI 网络插件 | Calico、Flannel、Cilium、Weave | 需操作宿主机网络接口、iptables 规则、eBPF 程序 |
| CSI 存储驱动 | Ceph CSI、NFS provisioner、Longhorn | 需在宿主机上 mount/umount 文件系统 |
| 容器运行时辅助 | containerd-shim、CRI-O 相关组件 | 直接管理容器进程和 cgroup |
| 安全监控 | Falco（内核模块模式）、sysdig | 加载内核模块或 eBPF 程序需要 SYS_ADMIN |
| 节点初始化 | init DaemonSet（如设置 sysctl、内核参数） | 需修改宿主机内核参数 |

**判断原则**：
- 这类组件通常由平台/SRE 团队维护，且以 DaemonSet 形式部署
- 应通过 Kyverno/OPA 策略将豁免范围限定在特定命名空间（如 `kube-system`）或特定 ServiceAccount
- 不因为平台组件需要特权就在业务命名空间放开 `privileged: true`

```yaml
# ✅ 示例：Kyverno 策略豁免特定命名空间的特权容器
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-privileged
    match:
      any:
      - resources:
          kinds: ["Pod"]
    exclude:
      any:
      - resources:
          namespaces: ["kube-system", "monitoring"]  # 平台命名空间豁免
    validate:
      message: "业务容器不允许使用 privileged 模式"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
```
