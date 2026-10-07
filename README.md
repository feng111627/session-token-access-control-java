# 基于令牌的认证、会话与访问控制

在本地内存中模拟用户与凭据，提供登录、刷新、鉴权与失败保护能力。
所有入口（登录、刷新、受保护资源）共享同一份计数与状态，结论一致且可解释。

## 令牌生命周期

```
登录 POST /auth/login  ──► 访问令牌(短期, 默认 300s) + 刷新令牌(长期, 默认 7 天)
                                │                        │
                                ▼                        ▼
                     访问 /api/** (Bearer)      刷新 POST /auth/refresh
                     过期 → 401 EXPIRED          轮换：旧令牌作废，发新令牌
```

- **访问令牌**：HMAC-SHA256 签名的三段式紧凑令牌（`header.payload.signature`），
  载荷含账号、角色、签发与过期时间。无状态校验。
- **刷新令牌**：不透明随机串，服务端内存存储。每次刷新**强制轮换**：
  旧令牌立即作废并返回新令牌。令牌按“家族”(family) 组织，同一账号重新登录会开启新家族并吊销旧家族。
- **重放检测**：已轮换过的旧刷新令牌被再次提交时，判定为泄露迹象，
  拒绝并**吊销整个家族**（包括合法用户当前持有的新令牌）。

### 拒绝原因（严格区分，不含糊）

| 场景 | HTTP | error | tokenRejectionReason |
|---|---|---|---|
| 无令牌 / 非 Bearer | 401 | `UNAUTHENTICATED` | — |
| 令牌格式非法 | 401 | `UNAUTHENTICATED` / `TOKEN_REJECTED` | `MALFORMED` |
| 签名不符（被篡改） | 401 | 同上 | `TAMPERED` |
| 令牌过期 | 401 | 同上 | `EXPIRED` |
| 刷新令牌重放 | 401 | `TOKEN_REJECTED` | `REUSED` |
| 刷新令牌不存在/已吊销 | 401 | `TOKEN_REJECTED` | `UNKNOWN_REFRESH_TOKEN` |
| 令牌类型用错 | 401 | 同上 | `WRONG_TOKEN_TYPE` |
| 账号已停用 | 401/403 | `UNAUTHENTICATED` / `ACCOUNT_DISABLED` | `ACCOUNT_DISABLED` |

账号被停用后：登录拒绝（403 `ACCOUNT_DISABLED`）、刷新拒绝并吊销其全部刷新令牌、
未过期的访问令牌也在过滤器处被拒绝。

## 鉴权模型

- 规则 = `(id, 路径模式, 角色集合, 资源范围)`，在 `application.properties` 的
  `security.policy.rules[*]` 下配置，按顺序匹配，命中即止，**无命中默认拒绝**。
- 资源范围由请求方法推导：`GET/HEAD → read`，其余 → `write`；规则可声明 `read/write/any`。
- 三种结论可区分：
  - **401 UNAUTHENTICATED** —— 未认证（无令牌或令牌被拒）
  - **403 FORBIDDEN** —— 已认证但越权（响应含 `policyVersion`、`ruleId`、`decisionId`）
  - **404 RESOURCE_NOT_FOUND** —— 通过鉴权但资源不存在
- **可复现性**：策略版本号是规则内容的 SHA-256 短哈希，相同规则集永远得到相同版本。
  每条判定都记录（内存 + 日志）请求要素、角色、策略版本、命中规则与理由；
  规则变更后历史版本快照保留在 `PolicyRegistry`，可用 `AuthorizationService.replay()`
  按当时版本复算，结论不随重启或请求顺序漂移。

## 限流与锁定

对登录失败做**按账号**与**按来源(IP)**双重计数（参数均可配置）：

| 参数 | 默认 | 含义 |
|---|---|---|
| `security.login.max-failures-per-account` | 5 | 账号在窗口内容许的失败次数 |
| `security.login.max-failures-per-source` | 20 | 来源在窗口内容许的失败次数 |
| `security.login.window-seconds` | 600 | 失败计数窗口 |
| `security.login.lock-seconds` | 300 | 锁定/限流时长，到期自动解除 |

- 达到阈值：账号锁定 → 423 `ACCOUNT_LOCKED`；来源限流 → 429 `RATE_LIMITED`；
  响应均带 `retryAfterSeconds`，等待时间可预期。
- 登录成功清零该账号的失败计数；来源计数保留，防止换账号试探。
- **并发安全**：`LoginAttemptLimiter.attempt()` 把“前置检查 → 凭据验证 → 计数/清零”
  放在同一把锁内，并发登录不会绕过阈值；`RefreshTokenStore` 的轮换同样在实例锁内完成，
  同一刷新令牌并发提交时恰好一个成功，其余按重放拒绝。

## 预置账号

| 账号 | 口令 | 角色 | 状态 |
|---|---|---|---|
| alice | alice-pass | ROLE_USER | 启用 |
| bob | bob-pass | ROLE_USER, ROLE_ADMIN | 启用 |
| carol | carol-pass | ROLE_USER | 停用（演示停用场景） |

## 本地验证

```bash
# 运行全部测试（令牌/重放/过期/越权/锁定/解锁/并发/端到端）
mvn test

# 启动服务（随机端口，可用 server.port=8080 固定）
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

# 登录
curl -s -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'

# 访问受保护资源
curl -s localhost:8080/api/documents/doc-1 -H "Authorization: Bearer <accessToken>"

# 刷新（旧刷新令牌再次提交将被判定为 REUSED）
curl -s -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'
```

测试日志中每个用例都会输出 `CASE ...` 行说明覆盖的业务与期望，
鉴权判定会输出 `authz decision #N ... outcome=... policyVersion=... rule=... reason=...`。
