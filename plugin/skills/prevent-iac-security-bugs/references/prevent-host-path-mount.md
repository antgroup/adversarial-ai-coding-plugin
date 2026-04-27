# 防范宿主机路径挂载与敏感目录暴露

## 目录

- [什么是宿主机路径挂载风险](#什么是宿主机路径挂载风险)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)
- [合理例外](#合理例外)

---

## 什么是宿主机路径挂载风险

将宿主机目录或文件挂载到容器中（`hostPath` volume），使得容器可以读写宿主机的文件系统。挂载敏感路径（如 `/`、`/etc`、`/var/run/docker.sock`）可直接导致容器逃逸或宿主机完全失陷。

**典型攻击场景**：
- 挂载 `/var/run/docker.sock`，容器内通过 Docker socket 启动特权容器实现逃逸
- 挂载宿主机 `/etc`，读取或篡改 `/etc/shadow`、`/etc/crontab`
- 挂载 `/`，容器拥有宿主机根目录完整读写权限
- 通过 `hostNetwork: true` + 挂载，访问宿主机网络栈和元数据接口

---

## 漏洞示例（禁止使用）

### 挂载 Docker Socket（危险）

```yaml
# ❌ 危险：挂载 Docker socket = 获得 Docker daemon 控制权 = 宿主机 root
spec:
  containers:
  - name: app
    volumeMounts:
    - name: docker-socket
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
```

### 挂载宿主机根目录或系统目录（危险）

```yaml
# ❌ 危险：挂载 / 或 /etc，容器可读写宿主机所有文件
spec:
  volumes:
  - name: host-root
    hostPath:
      path: /           # 宿主机根目录
  - name: host-etc
    hostPath:
      path: /etc        # 系统配置目录
  - name: host-proc
    hostPath:
      path: /proc       # 进程信息，可用于逃逸
```

### 使用 hostNetwork/hostPID/hostIPC（危险）

```yaml
# ❌ 危险：共享宿主机网络/PID/IPC 命名空间，容器可嗅探流量或干扰宿主机进程
spec:
  hostNetwork: true     # 共享宿主机网络命名空间
  hostPID: true         # 可看到宿主机所有进程
  hostIPC: true         # 可访问宿主机 IPC 资源
```

---

## 安全配置示例（推荐）

### 使用 emptyDir 代替 hostPath（临时存储）

```yaml
# ✅ 安全：临时文件使用 emptyDir，与宿主机完全隔离
spec:
  containers:
  - name: app
    volumeMounts:
    - name: tmp-dir
      mountPath: /tmp
    - name: cache-dir
      mountPath: /app/cache
  volumes:
  - name: tmp-dir
    emptyDir: {}
  - name: cache-dir
    emptyDir:
      sizeLimit: 500Mi    # 限制临时目录大小，防止磁盘耗尽
```

### 使用 PersistentVolumeClaim（持久存储）

```yaml
# ✅ 安全：持久化数据使用 PVC，通过存储系统隔离，不直接暴露宿主机路径
spec:
  containers:
  - name: app
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: app-data-pvc
```

### 必须使用 hostPath 时的最小化配置

```yaml
# ✅ 安全：确实需要 hostPath 时，使用只读挂载并限定具体路径
spec:
  containers:
  - name: log-collector
    volumeMounts:
    - name: app-logs
      mountPath: /host-logs
      readOnly: true              # 只读挂载
  volumes:
  - name: app-logs
    hostPath:
      path: /var/log/myapp        # 具体的日志路径，而非 / 或 /var/log
      type: Directory             # 明确类型，路径不存在时不会自动创建
```

### Kyverno 策略禁止危险挂载

```yaml
# ✅ 安全：集群策略层面禁止挂载敏感路径
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-path
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-hostpath
    match:
      any:
      - resources:
          kinds: ["Pod"]
    validate:
      message: "禁止使用 hostPath volume 挂载宿主机路径"
      deny:
        conditions:
          any:
          - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
            operator: GreaterThan
            value: "0"
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-namespaces
spec:
  validationFailureAction: Enforce
  rules:
  - name: no-host-namespace
    match:
      any:
      - resources:
          kinds: ["Pod"]
    validate:
      message: "禁止使用宿主机网络/PID/IPC 命名空间"
      pattern:
        spec:
          =(hostNetwork): false
          =(hostPID): false
          =(hostIPC): false
```

### CI/CD 中需要 Docker 能力时的替代方案

```yaml
# ✅ 安全：使用 kaniko 在容器内构建镜像，无需挂载 Docker socket
spec:
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - "--context=git://github.com/example/repo"
    - "--destination=registry.example.com/myapp:1.0"
    # 不需要 Docker socket，使用 Dockerfile 直接构建并推送
```

---

## 核心原则

- **避免 hostPath**：优先使用 `emptyDir`（临时）、PVC（持久），业务逻辑不需要直接访问宿主机文件系统
- **禁止共享命名空间**：`hostNetwork`、`hostPID`、`hostIPC` 默认都设为 `false`
- **拒绝 Docker socket**：CI/CD 镜像构建使用 kaniko/buildah 等无需 Docker daemon 的工具
- **策略层面强制**：通过 OPA/Kyverno 集群策略禁止危险挂载，不依赖 YAML 审查
- **只读挂载**：必须挂载宿主机路径时，`readOnly: true` 是最低要求

## 合理例外

以下基础设施组件使用 hostPath、hostNetwork 或 hostPID 是正常需求，不属于安全漏洞。这类组件通常以 DaemonSet 形式运行，不应与业务容器混用相同策略。

### 日志采集 Agent（hostPath 读取节点日志）

Fluentd、Filebeat、Promtail 等日志采集 DaemonSet 需要读取宿主机上的容器日志：

```yaml
# ✅ 合理：日志采集 agent 挂载节点日志目录（只读）
spec:
  containers:
  - name: fluentd
    volumeMounts:
    - name: varlog
      mountPath: /var/log
      readOnly: true              # 只读，不写入宿主机
    - name: varlibdockercontainers
      mountPath: /var/lib/docker/containers
      readOnly: true
  volumes:
  - name: varlog
    hostPath:
      path: /var/log
  - name: varlibdockercontainers
    hostPath:
      path: /var/lib/docker/containers
```

### 节点监控 Agent（hostNetwork + hostPID）

Prometheus node-exporter 需要 `hostNetwork` 采集宿主机网络指标；Falco 需要 `hostPID` 监控宿主机进程：

```yaml
# ✅ 合理：node-exporter DaemonSet 使用 hostNetwork 和 hostPID
spec:
  hostNetwork: true    # 采集宿主机网络接口指标
  hostPID: true        # 采集宿主机进程信息
  containers:
  - name: node-exporter
    securityContext:
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 65534
```

**判断原则**：
- 业务应用容器——严格禁止 hostPath、hostNetwork、hostPID
- 平台级 DaemonSet（日志、监控、安全扫描）——按最小化原则使用，只读优先，并通过 Kyverno/OPA 例外规则显式豁免，而非放开整个命名空间策略
