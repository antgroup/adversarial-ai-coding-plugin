# 防范越权访问安全编码规范

## 什么是越权访问

越权访问（Unauthorized Access）是指用户在未获得授权的情况下，访问或操作了不属于自己权限范围内的资源或功能。越权分为两类：

- **水平越权（Horizontal Privilege Escalation）**：同权限级别的用户访问了其他用户的数据。例如：用户 A 通过修改请求参数中的用户 ID，访问到了用户 B 的订单详情。
- **垂直越权（Vertical Privilege Escalation）**：低权限用户访问了高权限用户才能使用的功能。例如：普通用户通过直接访问管理员接口 URL，执行了删除用户的操作。

**典型攻击场景**：
- 修改请求中的资源 ID（如 `orderId=123` 改为 `orderId=456`）访问他人数据
- 直接访问管理后台接口，绕过前端菜单权限控制
- 通过枚举 ID 批量拉取其他用户的敏感信息

---

## 漏洞示例（禁止使用）

### 仅凭前端传参判断资源归属（危险）

```java
// ❌ 危险：直接使用前端传入的 userId 查询，未校验是否为当前登录用户
@GetMapping("/order/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    return orderService.findById(orderId);
}
```

```python
# ❌ 危险：直接使用请求参数中的 user_id，未与登录用户比对
@app.route('/profile')
def get_profile():
    user_id = request.args.get('user_id')
    return UserService.get_by_id(user_id)
```

### 仅依赖前端隐藏菜单控制权限（危险）

```java
// ❌ 危险：后端接口没有权限校验，仅靠前端不展示按钮来"保护"
@PostMapping("/admin/deleteUser")
public void deleteUser(@RequestParam Long userId) {
    userService.delete(userId);  // 任何人都可以直接调用此接口
}
```

---

## 安全编码示例（推荐）

### 水平越权：服务端强制绑定当前登录用户

所有涉及用户数据的查询和操作，必须从服务端的 Session/Token 中获取当前登录用户身份，并将其作为查询条件之一，**禁止信任客户端传入的用户 ID**。

```java
// ✅ 安全：从 Session 中获取当前用户，并作为查询条件
@GetMapping("/order/{orderId}")
public Order getOrder(@PathVariable Long orderId, HttpSession session) {
    Long currentUserId = (Long) session.getAttribute("userId");
    Order order = orderService.findByIdAndUserId(orderId, currentUserId);
    if (order == null) {
        throw new ForbiddenException("无权访问该订单");
    }
    return order;
}
```

```python
# ✅ 安全：从 Token 中解析当前用户，并与资源归属比对
@app.route('/profile')
@login_required
def get_profile():
    current_user_id = g.current_user.id  # 从认证上下文获取，非前端传参
    return UserService.get_by_id(current_user_id)
```

### 水平越权：查询时将用户 ID 作为过滤条件

```java
// ✅ 安全：SQL 查询中同时限定资源 ID 和所属用户 ID
// SELECT * FROM orders WHERE id = ? AND user_id = ?
Order order = orderMapper.findByIdAndUserId(orderId, currentUserId);
```

### 垂直越权：后端接口必须显式校验角色/权限

每个需要特定权限的接口，必须在后端进行显式的权限校验，不能依赖前端控制。

```java
// ✅ 安全：使用注解在后端强制校验角色
@PostMapping("/admin/deleteUser")
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(@RequestParam Long userId) {
    userService.delete(userId);
}
```

```python
# ✅ 安全：后端接口中显式校验用户角色
@app.route('/admin/delete_user', methods=['POST'])
@login_required
def delete_user():
    if not current_user.has_role('admin'):
        abort(403)
    user_id = request.json.get('user_id')
    UserService.delete(user_id)
```

### 通用原则：权限校验必须在服务端执行

```java
// ✅ 安全：封装统一的权限校验工具方法
public void assertResourceOwner(Long resourceOwnerId) {
    Long currentUserId = SecurityContext.getCurrentUserId();
    if (!currentUserId.equals(resourceOwnerId)) {
        throw new ForbiddenException("无权操作他人资源");
    }
}
```

---
