# Dockerfile 安全编写规范

## 目录

- [构建参数与凭据](#构建参数与凭据)
- [非 root 用户](#非-root-用户)
- [多阶段构建完整安全示例](#多阶段构建完整安全示例)
- [核心原则速查](#核心原则速查)

---

## 构建参数与凭据

```dockerfile
# ❌ 危险：ARG 的值会出现在镜像的 build history 中，docker history 可查看
ARG DB_PASSWORD
ENV DB_PASSWORD=${DB_PASSWORD}   # 永久固化在镜像层中

# ❌ 危险：RUN 命令中含凭据，该层被缓存后可被提取
RUN pip install --extra-index-url https://user:token@pypi.example.com/simple/ mypackage

# ✅ 安全：使用 BuildKit secret 挂载，不写入任何镜像层
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=pip_token \
    pip install --extra-index-url \
    "https://$(cat /run/secrets/pip_token)@pypi.example.com/simple/" mypackage
# 构建：docker build --secret id=pip_token,src=.pip_token .

# ✅ 安全：需要 SSH 访问时使用 ssh-agent 转发，不复制私钥
RUN --mount=type=ssh git clone git@github.com:example/private-repo.git
# 构建：docker build --ssh default .
```

---

## 非 root 用户

```dockerfile
# ❌ 危险：未指定 USER，容器默认以 root（UID 0）运行
FROM node:18-alpine
COPY . /app
CMD ["node", "/app/index.js"]

# ✅ 安全：创建专用非特权用户并切换
FROM node:18-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --chown=appuser:appgroup package*.json ./
RUN npm ci --only=production
COPY --chown=appuser:appgroup . .
USER appuser                    # 切换到非 root 用户
EXPOSE 3000
CMD ["node", "index.js"]
```

`--chown` 在 COPY 时直接设置归属，避免额外 RUN chown 产生额外镜像层。

---

## 多阶段构建完整安全示例

```dockerfile
# syntax=docker/dockerfile:1
# ✅ 安全：综合以上所有安全实践的完整示例
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci                        # 安装全部依赖（含 devDependencies）
COPY src/ ./src/
COPY tsconfig.json ./
RUN npm run build

# 生产运行镜像
FROM node:18-alpine AS runtime
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app

# 只复制生产依赖和构建产物
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist

USER appuser
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js"]
```

---

## 核心原则速查

| 项目 | 规范 |
|---|---|
| 构建凭据 | `--mount=type=secret`，禁止 ARG/ENV 存凭据 |
| 运行用户 | 创建专用非 root 用户，`USER` 指令切换 |
| 镜像标签 | 指定精确版本（`node:18.20.4-alpine`），禁止 `latest` |
| 多阶段构建 | 生产镜像只包含运行时产物，不包含源码、构建工具、devDependencies |
| HEALTHCHECK | 配置健康检查，容器异常时 orchestrator 可自动重启 |
| CMD/ENTRYPOINT | 使用 JSON 数组格式（exec form），避免 shell form 引入额外 shell 进程 |