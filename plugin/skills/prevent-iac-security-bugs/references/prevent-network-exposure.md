# 防范网络暴露与网络策略缺失

## 目录

- [什么是网络暴露风险](#什么是网络暴露风险)
- [漏洞示例（禁止使用）](#漏洞示例禁止使用)
- [安全配置示例（推荐）](#安全配置示例推荐)
- [核心原则](#核心原则)
- [合理例外](#合理例外)

---

## 什么是网络暴露风险

Kubernetes 默认允许集群内所有 Pod 互相通信，未配置 NetworkPolicy 时任何 Pod 都能访问数据库、内部服务和元数据接口。错误的 Service 类型、无限制的 Ingress 规则，以及暴露在公网的管理端口，都是常见的网络暴露根因。

**典型攻击场景**：
- 数据库 Pod 无 NetworkPolicy 保护，任意被攻破的 Pod 可直接连接数据库端口
- Service 类型错误配置为 `LoadBalancer`，数据库直接暴露到公网
- 管理接口（Kubernetes Dashboard、etcd、kubelet API）监听在公网可访问的地址
- `0.0.0.0` 绑定的调试端口随容器镜像暴露

---

## 漏洞示例（禁止使用）

### 数据库 Service 暴露为 LoadBalancer（危险）

```yaml
# ❌ 危险：数据库直接暴露到公网，任何人可尝试连接
apiVersion: v1
kind: Service
metadata:
  name: mysql-service
spec:
  type: LoadBalancer      # 申请公网 IP
  ports:
  - port: 3306
  selector:
    app: mysql
```

### 无 NetworkPolicy（危险）

```yaml
# ❌ 危险：没有 NetworkPolicy，集群内所有 Pod 默认互通
# 任何被攻破的 Pod 都可以访问数据库、内部 API、云元数据接口
```

### Ingress 无限制通配符（危险）

```yaml
# ❌ 危险：未限制来源 IP，管理后台直接暴露给所有 Internet 用户
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
spec:
  rules:
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: admin-service
            port:
              number: 8080
```

---

## 安全配置示例（推荐）

### 按需开放白名单

```yaml
# ✅ 安全：只允许 app 层访问数据库，其他 Pod 无法连接
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: mysql                    # 保护数据库 Pod
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend              # 只允许 backend Pod 访问
    - namespaceSelector:
        matchLabels:
          name: production          # 限定命名空间
    ports:
    - protocol: TCP
      port: 3306
```

### 限制对外出站（防 SSRF/数据渗漏）

```yaml
# ✅ 安全：只允许特定出站目标，防止容器访问云元数据接口或内网服务
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: production
    ports:
    - protocol: TCP
      port: 3306                   # 只允许访问数据库
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32       # 屏蔽云元数据接口
        - 10.0.0.0/8               # 屏蔽内网（按实际情况调整）
    ports:
    - protocol: TCP
      port: 443                    # 只允许 HTTPS 出站
```

### 管理后台 Ingress 限制来源 IP

```yaml
# ✅ 安全：通过注解限制只有运维 IP 段可访问管理后台
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "203.0.113.0/24,10.0.0.0/8"
spec:
  rules:
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: admin-service
            port:
              number: 8080
```

### Service 类型选择

```yaml
# ✅ 安全：内部服务使用 ClusterIP（默认），不对外暴露
apiVersion: v1
kind: Service
metadata:
  name: database-service
spec:
  type: ClusterIP           # 只在集群内可访问
  ports:
  - port: 3306
  selector:
    app: mysql
```

---

## 核心原则

- **最小暴露面**：内部服务用 `ClusterIP`，需要外部访问的通过 Ingress 控制器统一收口
- **屏蔽元数据接口**：在 Egress 策略中明确排除 `169.254.169.254`（AWS/GCP/阿里云元数据接口）
- **管理接口隔离**：Dashboard、监控、日志等管理接口不暴露到公网，使用 VPN 或 kubectl port-forward 访问

## 合理例外

以下场景使用 LoadBalancer 或 NodePort 是正常业务需求，不属于安全漏洞：

- **对外暴露的业务服务**（Web API、公网网关）必须使用 LoadBalancer，应通过 SecurityGroup/防火墙规则 + Ingress + WAF 控制访问，而非避免使用 LoadBalancer 本身
- **裸金属集群或无云 LB 环境**中，NodePort 是对外暴露服务的标准方式，此时应结合外部负载均衡器（如 HAProxy、MetalLB）控制暴露范围
- **监控和日志组件**（Prometheus、Grafana）使用 NodePort 对内网暴露是常见运维方式，不应与公网暴露混为一谈
