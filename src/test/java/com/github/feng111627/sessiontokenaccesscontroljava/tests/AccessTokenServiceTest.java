package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务域：访问令牌生命周期（签发、校验、过期、篡改、格式错误）。
 */
class AccessTokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenServiceTest.class);
    private static final long TTL = 60_000;

    private MutableClock clock;
    private AccessTokenService service;

    @BeforeEach
    void setUp(TestInfo info) {
        clock = new MutableClock(1_000_000);
        service = new AccessTokenService("test-secret", TTL, clock);
        log.info("[访问令牌] 用例: {}", info.getDisplayName());
    }

    @Test
    @DisplayName("签发后可校验出主体、角色与时间声明")
    void issueAndVerify() {
        String token = service.issue("alice", Set.of("USER"));
        AccessTokenClaims claims = service.verify(token);
        assertEquals("alice", claims.subject());
        assertEquals(Set.of("USER"), claims.roles());
        assertEquals(1_000_000 + TTL, claims.expiresAtEpochMs());
        log.info("[访问令牌] 签发校验通过, jti={}", claims.tokenId());
    }

    @Test
    @DisplayName("过期令牌被拒绝且原因码为 TOKEN_EXPIRED")
    void expiredTokenRejected() {
        String token = service.issue("alice", Set.of("USER"));
        clock.advanceMillis(TTL); // 恰好到达过期时刻
        AuthException ex = assertThrows(AuthException.class, () -> service.verify(token));
        assertEquals(AuthErrorCode.TOKEN_EXPIRED, ex.getCode());
        log.info("[访问令牌] 过期拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("被篡改的令牌被拒绝且原因码为 TOKEN_TAMPERED")
    void tamperedTokenRejected() {
        String token = service.issue("alice", Set.of("USER"));
        // 篡改 payload：把 alice 改成 admin 后重新编码（无密钥重签）
        String[] parts = token.split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        String forged = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.replace("alice", "admin").getBytes()) + "." + parts[1];
        AuthException ex = assertThrows(AuthException.class, () -> service.verify(forged));
        assertEquals(AuthErrorCode.TOKEN_TAMPERED, ex.getCode());
        log.info("[访问令牌] 篡改拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("格式错误的令牌被拒绝且原因码为 TOKEN_MALFORMED")
    void malformedTokenRejected() {
        AuthException ex = assertThrows(AuthException.class, () -> service.verify("not-a-token"));
        assertEquals(AuthErrorCode.TOKEN_MALFORMED, ex.getCode());
        log.info("[访问令牌] 格式错误拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("不同密钥签发的令牌视为篡改")
    void wrongSecretRejected() {
        AccessTokenService other = new AccessTokenService("other-secret", TTL, clock);
        String foreign = other.issue("alice", Set.of("USER"));
        AuthException ex = assertThrows(AuthException.class, () -> service.verify(foreign));
        assertEquals(AuthErrorCode.TOKEN_TAMPERED, ex.getCode());
        log.info("[访问令牌] 异密钥拒绝, code={}", ex.getCode());
    }
}
