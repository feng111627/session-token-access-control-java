# 会话令牌与访问控制（内存版）

基于 Spring Boot 的认证 / 会话 / 访问控制示例：本地内存模拟用户与凭据，
覆盖登录、令牌刷新、鉴权与失败保护，各入口下结论一致且可解释。

## 架构一览

| 模块 | 类 | 职责 |
|------|----|------|
| token | `AccessTokenService` | 访问令牌签发/校验（HMAC-SHA256 签名） |
| token | `RefreshTokenStore` | 刷新令牌签发、轮换、重放识别、吊销 |
| auth  | `UserDirectory` | 内存用户库（加盐哈希口令） |
| auth  | `LoginAttemptGuard` | 按账号 + 按来源的失败限流与临时锁定 |
| auth  | `AuthService` | 登录/刷新编排 |
| access| `AccessPolicy` / `AuthorizationService` | 角色 + 资源范围鉴权（规则带版本、评估为纯函数） |
| web   | `AuthController` / `ResourceController` / `AuthInterceptor` / `ApiErrorHandler` | HTTP 入口与错误映射 |

## 令牌生命周期

```
登录 POST /auth/login  ──► 访问令牌(短期, 默认120s) + 刷新令牌(长期, 默认1h)
                                  │                        │
                GET /api/** 携带 Bearer 访问令牌      POST /auth/refresh
                                  │                        ▼
                                  │              轮换：旧刷新令牌立即作废(ROTATED)，
                                  │              颁发新刷新令牌 + 新访问令牌
                                  ▼
                    过期/篡改/格式错误分别返回 TOKEN_EXPIRED / TOKEN_TAMPERED / TOKEN_MALFORMED
```

- **访问令牌**：`base64url(payload).base64url(hmac)`，payload 含 `sub/roles/iat/exp/jti`；
  校验失败按 `TOKEN_MALFORMED` / `TOKEN_TAMPERED` / `TOKEN_EXPIRED` 区分。
- **刷新令牌**：服务端保存的不透明随机串，状态机 `ACTIVE -> ROTATED / REVOKED`。
  - 每次刷新必须轮换，旧令牌立即作废；
  - 再次提交已轮换/已吊销令牌 → `REFRESH_TOKEN_REUSED`（重放识别）；
  - 未知令牌 → `REFRESH_TOKEN_UNKNOWN`；过期 → `REFRESH_TOKEN_EXPIRED`；
  - 账号被停用时刷新 → `ACCOUNT_DISABLED`，并吊销该账号全部刷新令牌。
- **并发安全**：轮换的“校验-作废-签发”三步在同一临界区完成，
  并发提交同一刷新令牌时恰好一个成功，其余全部判定为重放（有测试覆盖）。

## 鉴权模型

- 规则配置（`application.properties`）：`security.rules[i]=resource:action:ROLE1,ROLE2`，
  已知资源列表 `security.resources`，规则版本 `security.rule-version`。
- 评估顺序可区分三种拒绝：
  1. 未携带/非法令牌 → `UNAUTHENTICATED`(401)；
  2. 资源不在已知列表 → `RESOURCE_NOT_FOUND`(404)；
  3. 已认证但角色不满足任何匹配规则 → `FORBIDDEN`(403)。
- **可复现性**：评估是关于 `(claims, resource, action, policy)` 的纯函数，
  结论中携带 `ruleVersion`；同样输入 + 同样规则版本必然得到同样结论，
  与重启、请求顺序无关（有测试覆盖）。

## 限流与锁定

- 同一**账号**或同一**来源**（`X-Forwarded-For` 首跳，否则远端地址）连续失败
  达到 `security.login-max-failures`（默认 5）次即锁定
  `security.login-lock-millis`（默认 300s）。
- 账号锁定 → `ACCOUNT_LOCKED`(429)，来源锁定 → `SOURCE_LOCKED`(429)，
  锁定截止时间确定（`失败时刻 + lockMillis`），到期惰性自动解锁，无需后台线程。
- 登录成功立即清零对应账号与来源的计数。
- 所有计数在内部锁下读写，并发登录不会绕过限流（有测试覆盖）。

## 错误码总表

| code | HTTP | 含义 |
|------|------|------|
| INVALID_CREDENTIALS | 401 | 用户名不存在或口令错误 |
| ACCOUNT_DISABLED | 403 | 账号已停用 |
| ACCOUNT_LOCKED / SOURCE_LOCKED | 429 | 账号/来源临时锁定 |
| TOKEN_MALFORMED / TOKEN_TAMPERED / TOKEN_EXPIRED | 401 | 访问令牌格式错/被篡改/已过期 |
| REFRESH_TOKEN_UNKNOWN / REUSED / EXPIRED | 401 | 刷新令牌未知/已使用(重放)/已过期 |
| UNAUTHENTICATED | 401 | 未携带访问令牌 |
| FORBIDDEN | 403 | 已认证但越权 |
| RESOURCE_NOT_FOUND | 404 | 资源不存在 |

## 本地验证

```bash
# 运行全部测试（34 个用例，日志按业务域标注：访问令牌/刷新令牌/限流锁定/登录编排/鉴权/Web链路）
mvn test

# 启动服务
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080

# 登录（预置账号：admin/admin123, alice/alice123, bob/bob123[已停用]）
curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice123"}'

# 访问资源（documents:read 允许 USER；admin-console 需要 ADMIN）
curl -s "localhost:8080/api/resources/documents?action=read" -H "Authorization: Bearer <accessToken>"

# 刷新（旧刷新令牌再次提交会返回 REFRESH_TOKEN_REUSED）
curl -s -X POST localhost:8080/auth/refresh -H 'Content-Type: application/json' \
     -d '{"refreshToken":"<refreshToken>"}'
```

## 测试覆盖

| 测试类 | 业务域 | 关键用例 |
|--------|--------|----------|
| `AccessTokenServiceTest` | 访问令牌 | 签发校验、过期边界、篡改、异密钥、格式错误 |
| `RefreshTokenStoreTest` | 刷新令牌 | 轮换、重放、未知、过期、吊销、16 线程并发轮换唯一胜者 |
| `LoginAttemptGuardTest` | 限流锁定 | 阈值锁定、精确到毫秒的自动解锁、账号/来源双维度、成功复位、并发不绕过 |
| `AuthServiceTest` | 登录编排 | 成功颁发、失败→锁定→解锁链路、停用账号登录/刷新、刷新轮换+重放 |
| `AuthorizationServiceTest` | 鉴权 | ALLOW/FORBIDDEN/UNAUTHENTICATED/NOT_FOUND 区分、判定可复现、规则版本迁移 |
| `WebFlowIntegrationTest` | Web 链路 | 登录→访问→刷新→重放全链路、未认证/篡改/越权/不存在/停用的状态码与错误码 |
