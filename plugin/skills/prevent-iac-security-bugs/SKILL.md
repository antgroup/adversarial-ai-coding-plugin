---
name: prevent-iac-security-bugs
description: >
  当用户需要编写、修改或审查基础设施配置文件时，应当使用此技能。包括但不限于：
  "写 k8s yaml"、"配置 Kubernetes"、"写 Deployment"、"创建 Pod"、"配置 Service"、
  "写 Dockerfile"、"docker-compose 配置"、"Helm chart"、"Terraform 配置"、
  "写 NetworkPolicy"、"配置 RBAC"、"ServiceAccount 权限"、"容器安全配置"、
  "配置 Secret"、"ConfigMap 配置"、"PodSecurityContext"、"镜像配置"。
  即使用户没有提到"安全"或"漏洞"，只要涉及容器、k8s、IaC 配置文件的编写或修改，都应触发此技能。
---

# IaC 安全配置生成规范

IaC 配置错误（如特权容器、凭据明文、无网络策略）一旦部署到生产集群，修复成本极高，且可能已造成入侵或数据泄露。在编写配置时消除漏洞，是最低成本的防护手段。

## 工作流程

按以下三步执行安全配置生成，每步都为后续步骤提供安全保障。

### 第一步：识别安全风险

分析用户需求，对照下表判断哪些风险类型适用于当前场景。**识别出的每一个风险类型都需要处理，不得遗漏。**

| 风险类型 | 触发场景 | 参考文档 |
|---|---|---|
| 特权容器与 root 运行 | 配置 Pod/容器；涉及 securityContext；容器以何种用户运行 | `references/prevent-privileged-containers.md` |
| 凭据硬编码 | env 中含密码/key；ConfigMap 存敏感数据；Dockerfile ENV 含凭据；Terraform/compose 含明文密码 | `references/prevent-hardcoded-secrets.md` |
| 网络暴露与策略缺失 | 配置 Service（尤其 LoadBalancer/NodePort）；未见 NetworkPolicy；Ingress 规则；涉及端口暴露 | `references/prevent-network-exposure.md` |
| Dockerfile 安全编写 | 编写或修改 Dockerfile；涉及 ADD/COPY、ARG/ENV、USER、CMD、HEALTHCHECK、.dockerignore | `references/prevent-dockerfile-security.md` |
| RBAC 过度授权 | 创建/修改 Role/ClusterRole；配置 ServiceAccount；权限绑定；涉及通配符权限 | `references/prevent-rbac-misconfiguration.md` |
| 宿主机路径挂载 | 配置 volume；使用 hostPath；涉及 Docker socket；hostNetwork/hostPID 配置 | `references/prevent-host-path-mount.md` |
| Capabilities 滥用 | 配置 securityContext.capabilities；涉及特殊系统权限；网络监控/调试场景 | `references/prevent-capabilities-misconfiguration.md` |

### 第二步：查阅安全编码规范

对第一步中**每一个**识别出的风险类型，读取对应的参考文档后再进入第三步。

### 第三步：生成符合安全规范的配置

在完整理解安全规范后，按以下原则完成用户需求：

- **默认安全**：默认禁用特权（`privileged: false`、`allowPrivilegeEscalation: false`）、默认只读根文件系统、默认 Drop ALL Capabilities
- **网络最小暴露**：内部服务使用 ClusterIP，按需精确开放入站/出站白名单，管理接口不对公网暴露
- **凭据外置**：密码、Token、Key 通过 Secret 或外部 KMS 管理，不写入 ConfigMap 或 env value
- **最小权限**：RBAC 精确到 verb + resource + resourceName，ServiceAccount 默认禁止挂载 token
- **镜像固定**：生产配置使用精确版本标签或 digest，禁止 latest

---

## 参考资源

- **`references/prevent-privileged-containers.md`** — 特权容器与 root 运行防范
- **`references/prevent-hardcoded-secrets.md`** — 凭据硬编码防范（k8s Secret、Vault、KMS）
- **`references/prevent-network-exposure.md`** — 网络暴露与 NetworkPolicy 配置
- **`references/prevent-dockerfile-security.md`** — Dockerfile 安全编写规范（ADD/COPY、构建凭据、USER、HEALTHCHECK、.dockerignore）
- **`references/prevent-rbac-misconfiguration.md`** — RBAC 过度授权防范
- **`references/prevent-host-path-mount.md`** — 宿主机路径挂载与逃逸防范
- **`references/prevent-capabilities-misconfiguration.md`** — Linux Capabilities 滥用防范
