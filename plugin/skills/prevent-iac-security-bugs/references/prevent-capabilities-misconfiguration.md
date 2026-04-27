# 防范 Linux Capabilities 滥用与不安全配置

## 目录

- [什么是 Capabilities 滥用](#什么是-capabilities-滥用)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)
- [合理例外](#合理例外)

---

## 什么是 Capabilities 滥用

Linux Capabilities 将传统 root 权限拆分为独立的细粒度能力（如网络配置、挂载文件系统、调试进程等）。在容器中保留或添加不必要的 Capability，会为攻击者提供逃逸或横向移动的手段，即使容器不是以完整 root 权限运行。

**典型攻击场景**：
- 保留 `CAP_SYS_ADMIN`：权限接近 root，可挂载文件系统、加载内核模块、执行多种特权操作
- 保留 `CAP_NET_RAW`：可进行 ARP 欺骗、网络嗅探，攻击同节点其他 Pod
- 保留 `CAP_SYS_PTRACE`：可附加到同节点进程进行调试和内存读取
- 添加 `CAP_DAC_OVERRIDE`：可绕过文件权限检查，读取宿主机任意文件

---

## 漏洞示例（禁止使用）

### 未 drop 任何 Capabilities（危险）

```yaml
# ❌ 危险：Docker 默认给容器保留约 14 个 Capabilities，未显式 drop 则全部保留
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      # 无 capabilities 配置，默认保留 CHOWN、DAC_OVERRIDE、FOWNER、NET_RAW 等
```

### 添加高危 Capabilities（危险）

```yaml
# ❌ 危险：显式添加危险 Capability
spec:
  containers:
  - name: app
    securityContext:
      capabilities:
        add:
          - SYS_ADMIN     # 接近 root 权限
          - SYS_PTRACE    # 可附加调试任意进程
          - NET_ADMIN     # 可修改网络配置
```

### 未设置 seccompProfile（危险）

```yaml
# ❌ 危险：没有 seccomp 过滤，容器可调用任意系统调用
spec:
  containers:
  - name: app
    # 无 seccompProfile，攻击者可利用内核 syscall 漏洞
```

---

## 安全配置示例（推荐）

### Drop ALL + 按需 Add（最小权限基线）

```yaml
# ✅ 安全：先 drop 所有 Capabilities，再按业务需要精确 add
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL                          # 丢弃所有默认 Capabilities
        add:
          - NET_BIND_SERVICE             # 仅当需要绑定 <1024 端口时添加（通常不需要，用高端口代替）
```

### 完整安全 securityContext 示例

```yaml
# ✅ 安全：完整的容器安全基线配置
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault               # 启用默认 seccomp 过滤（推荐所有 Pod 启用）
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
```

### 需要网络监控的场景（精确授权）

```yaml
# ✅ 安全：网络监控场景只授予必需的 NET_RAW，而非 NET_ADMIN 或 SYS_ADMIN
spec:
  containers:
  - name: network-monitor
    securityContext:
      capabilities:
        drop:
          - ALL
        add:
          - NET_RAW       # 仅用于原始套接字，范围最小化
```
### Seccomp 自定义 Profile（高安全要求场景）

```yaml
# ✅ 安全：使用自定义 seccomp profile 精确限制允许的系统调用
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/myapp-seccomp.json   # 引用节点上的自定义 profile
  containers:
  - name: app
    securityContext:
      capabilities:
        drop:
          - ALL
```

```json
// myapp-seccomp.json 结构示例（实际 syscall 白名单建议用 strace 或 inspektor-gadget 采集后裁剪）
// 参考：https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": ["read", "write", "open", "close", "stat", "exit_group", "..."],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

> 生产环境建议用 `strace -f` 或 [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget) 采集真实 syscall，再生成精确白名单，而非手工维护完整列表。

---

## 核心原则

- **Drop ALL 是基线**：所有容器都应 `drop: [ALL]`，再按需精确 add
- **不加 SYS_ADMIN**：`CAP_SYS_ADMIN` 接近完整 root 权限，几乎所有业务都不需要
- **seccomp 补充防御**：Capabilities 控制"能做什么"，seccomp 控制"能调用哪些 syscall"，两者配合使用
- **业务容器避免 NET_RAW**：Docker 默认保留此 Capability，业务容器显式 drop 后可防止网络嗅探攻击
- **高端口绕过 NET_BIND_SERVICE**：应用监听 8080 而非 80，无需此 Capability

## 合理例外

以下场景添加特定 Capability 是合理业务需求，不属于安全漏洞：

| Capability | 合理使用场景 |
|---|---|
| `NET_RAW` | `ping`、`traceroute`、`arping` 等网络诊断工具；部分 CNI 健康探针；网络测试容器 |
| `SYS_PTRACE` | 性能分析工具（async-profiler、Java Flight Recorder、perf）；调试 sidecar 容器 |
| `NET_BIND_SERVICE` | 必须监听 80/443 端口的容器（应优先改用高端口 + Ingress，但历史系统不总能改造） |

**判断原则**：
- 业务应用容器——严格 Drop ALL，杜绝例外
- 基础设施/工具容器（监控 agent、网络诊断、CI runner）——按最小化原则精确 add，并在注释中说明原因
- 若不确定某个 Capability 是否必要，用 `docker run --cap-drop=ALL --cap-add=XXX` 测试后再决定
