package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("端到端：登录→访问→刷新→重放，各入口结论一致且可区分")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WebEndpointsTest {

    private static final Logger log = LoggerFactory.getLogger(WebEndpointsTest.class);

    @Autowired
    private TestRestTemplate http;

    @SuppressWarnings("unchecked")
    private Map<String, Object> login(String username, String password) {
        ResponseEntity<Map> resp = http.postForEntity("/auth/login",
                Map.of("username", username, "password", password), Map.class);
        assertEquals(200, resp.getStatusCode().value());
        return resp.getBody();
    }

    private HttpEntity<?> bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }

    @Test
    @DisplayName("完整链路：登录→访问资源→刷新→旧刷新令牌重放被拒")
    void fullLifecycle() {
        log.info("CASE 端到端: 登录→200→刷新→重放旧令牌期望 401/REUSED");
        Map<String, Object> tokens = login("alice", "alice-pass");
        String access = (String) tokens.get("accessToken");
        String refresh = (String) tokens.get("refreshToken");

        ResponseEntity<Map> ok = http.exchange("/api/documents/doc-1", HttpMethod.GET, bearer(access), Map.class);
        assertEquals(200, ok.getStatusCode().value());

        ResponseEntity<Map> refreshed = http.postForEntity("/auth/refresh",
                Map.of("refreshToken", refresh), Map.class);
        assertEquals(200, refreshed.getStatusCode().value());
        assertNotEquals(refresh, refreshed.getBody().get("refreshToken"));

        ResponseEntity<Map> replay = http.postForEntity("/auth/refresh",
                Map.of("refreshToken", refresh), Map.class);
        assertEquals(401, replay.getStatusCode().value());
        assertEquals("TOKEN_REJECTED", replay.getBody().get("error"));
        assertEquals("REUSED", replay.getBody().get("tokenRejectionReason"));
    }

    @Test
    @DisplayName("未认证 / 越权 / 资源不存在三种结论可区分")
    void distinguishableOutcomes() {
        log.info("CASE 三态区分: 无令牌=401, 越权=403, 资源不存在=404");
        ResponseEntity<Map> noToken = http.getForEntity("/api/documents/doc-1", Map.class);
        assertEquals(401, noToken.getStatusCode().value());
        assertEquals("UNAUTHENTICATED", noToken.getBody().get("error"));

        Map<String, Object> tokens = login("alice", "alice-pass");
        String access = (String) tokens.get("accessToken");

        ResponseEntity<Map> forbidden = http.exchange("/api/admin/stats", HttpMethod.GET, bearer(access), Map.class);
        assertEquals(403, forbidden.getStatusCode().value());
        assertEquals("FORBIDDEN", forbidden.getBody().get("error"));
        assertNotNull(forbidden.getBody().get("policyVersion"));

        ResponseEntity<Map> notFound = http.exchange("/api/documents/doc-999", HttpMethod.GET, bearer(access), Map.class);
        assertEquals(404, notFound.getStatusCode().value());
        assertEquals("RESOURCE_NOT_FOUND", notFound.getBody().get("error"));
    }

    @Test
    @DisplayName("篡改的访问令牌被拒，原因=TAMPERED")
    void tamperedAccessToken() {
        log.info("CASE 篡改令牌: 期望 401 + TAMPERED");
        Map<String, Object> tokens = login("alice", "alice-pass");
        String access = (String) tokens.get("accessToken");
        String forged = access.substring(0, access.length() - 2) + "xx";
        ResponseEntity<Map> resp = http.exchange("/api/documents/doc-1", HttpMethod.GET, bearer(forged), Map.class);
        assertEquals(401, resp.getStatusCode().value());
        assertEquals("TAMPERED", resp.getBody().get("tokenRejectionReason"));
    }

    @Test
    @DisplayName("管理员可访问 admin 路径，普通用户写文档成功")
    void roleBasedAccess() {
        log.info("CASE 角色访问: bob(ADMIN) 访问 /api/admin/stats=200; alice 写文档=201");
        Map<String, Object> bobTokens = login("bob", "bob-pass");
        ResponseEntity<Map> stats = http.exchange("/api/admin/stats", HttpMethod.GET,
                bearer((String) bobTokens.get("accessToken")), Map.class);
        assertEquals(200, stats.getStatusCode().value());

        Map<String, Object> aliceTokens = login("alice", "alice-pass");
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth((String) aliceTokens.get("accessToken"));
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<Map> created = http.exchange("/api/documents", HttpMethod.POST,
                new HttpEntity<>(Map.of("title", "notes"), headers), Map.class);
        assertEquals(201, created.getStatusCode().value());
        assertEquals("alice", created.getBody().get("owner"));
    }

    @Test
    @DisplayName("登录失败响应可区分：口令错误=401，锁定=423 且带 retryAfterSeconds")
    void loginFailureOutcomes() {
        log.info("CASE 登录失败: 错误口令=401/INVALID_CREDENTIALS; 连续失败后=423/ACCOUNT_LOCKED");
        ResponseEntity<Map> bad = http.postForEntity("/auth/login",
                Map.of("username", "mallory", "password", "x"), Map.class);
        assertEquals(401, bad.getStatusCode().value());
        assertEquals("INVALID_CREDENTIALS", bad.getBody().get("error"));

        for (int i = 0; i < 5; i++) {
            http.postForEntity("/auth/login", Map.of("username", "dave", "password", "x"), Map.class);
        }
        ResponseEntity<Map> locked = http.postForEntity("/auth/login",
                Map.of("username", "dave", "password", "x"), Map.class);
        assertEquals(423, locked.getStatusCode().value());
        assertEquals("ACCOUNT_LOCKED", locked.getBody().get("error"));
        assertNotNull(locked.getBody().get("retryAfterSeconds"));
    }
}
