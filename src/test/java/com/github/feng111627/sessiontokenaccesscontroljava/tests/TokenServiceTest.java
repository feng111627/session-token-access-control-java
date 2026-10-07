package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenRejectionReason;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("访问令牌：签发、篡改、过期、类型误用")
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private MutableClock clock;
    private TokenService tokens;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        tokens = new TokenService(clock, "test-secret", 300);
    }

    @Test
    @DisplayName("签发的令牌可通过校验并还原账号与角色")
    void issueAndVerify() {
        log.info("CASE 签发与校验: 期望 subject/roles 还原, TTL=300s");
        String token = tokens.issueAccessToken("alice", Set.of("ROLE_USER"));
        TokenService.AccessToken parsed = tokens.verifyAccessToken(token);
        assertEquals("alice", parsed.subject());
        assertTrue(parsed.hasRole("ROLE_USER"));
        assertEquals(300, parsed.expiresAtEpochSeconds() - parsed.issuedAtEpochSeconds());
    }

    @Test
    @DisplayName("篡改 payload 后签名校验失败，原因=TAMPERED")
    void tamperedPayloadRejected() {
        log.info("CASE 令牌篡改: 修改 payload 段, 期望 TAMPERED");
        String token = tokens.issueAccessToken("alice", Set.of("ROLE_USER"));
        String[] parts = token.split("\\.");
        String forged = parts[0] + "." + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("sub=admin;roles=ROLE_ADMIN;type=access;iat=1;exp=9999999999".getBytes())
                + "." + parts[2];
        AuthException e = assertThrows(AuthException.class, () -> tokens.verifyAccessToken(forged));
        assertEquals(TokenRejectionReason.TAMPERED, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("过期令牌被拒绝，原因=EXPIRED")
    void expiredTokenRejected() {
        log.info("CASE 令牌过期: 时钟推进 301s, 期望 EXPIRED");
        String token = tokens.issueAccessToken("alice", Set.of("ROLE_USER"));
        clock.advanceSeconds(301);
        AuthException e = assertThrows(AuthException.class, () -> tokens.verifyAccessToken(token));
        assertEquals(TokenRejectionReason.EXPIRED, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("格式非法的令牌被拒绝，原因=MALFORMED")
    void malformedTokenRejected() {
        log.info("CASE 格式非法: 非三段结构, 期望 MALFORMED");
        AuthException e = assertThrows(AuthException.class, () -> tokens.verifyAccessToken("not-a-token"));
        assertEquals(TokenRejectionReason.MALFORMED, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("不同密钥签发的令牌被拒绝，原因=TAMPERED")
    void wrongSecretRejected() {
        log.info("CASE 密钥不匹配: 用另一密钥验签, 期望 TAMPERED");
        TokenService other = new TokenService(clock, "other-secret", 300);
        String token = other.issueAccessToken("alice", Set.of("ROLE_USER"));
        AuthException e = assertThrows(AuthException.class, () -> tokens.verifyAccessToken(token));
        assertEquals(TokenRejectionReason.TAMPERED, e.tokenRejectionReason());
    }
}
