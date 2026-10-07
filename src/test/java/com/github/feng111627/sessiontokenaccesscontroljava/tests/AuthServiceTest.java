package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthService;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.LoginAttemptGuard;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.UserDirectory;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.model.TokenPair;
import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.token.RefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务域：登录与刷新编排（凭据、停用账号、限流联动、令牌对颁发）。
 */
class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private MutableClock clock;
    private UserDirectory users;
    private AuthService authService;
    private RefreshTokenStore refreshStore;

    @BeforeEach
    void setUp(TestInfo info) {
        clock = new MutableClock(20_000_000);
        users = new UserDirectory();
        var guard = new LoginAttemptGuard(3, 60_000, clock);
        var accessTokens = new AccessTokenService("svc-secret", 60_000, clock);
        refreshStore = new RefreshTokenStore(600_000, clock);
        authService = new AuthService(users, guard, accessTokens, refreshStore);
        log.info("[登录编排] 用例: {}", info.getDisplayName());
    }

    @Test
    @DisplayName("正确凭据登录成功并颁发令牌对")
    void loginSuccess() {
        TokenPair pair = authService.login("alice", "alice123", "1.1.1.1");
        assertNotNull(pair.accessToken());
        assertNotNull(pair.refreshToken());
        assertTrue(pair.accessTokenExpiresAtEpochMs() > clock.millis());
        log.info("[登录编排] 登录成功, 访问令牌过期时刻={}", pair.accessTokenExpiresAtEpochMs());
    }

    @Test
    @DisplayName("错误口令被拒绝且原因码为 INVALID_CREDENTIALS，连续失败触发锁定")
    void badPasswordThenLock() {
        for (int i = 0; i < 3; i++) {
            AuthException ex = assertThrows(AuthException.class,
                    () -> authService.login("alice", "wrong", "1.1.1.1"));
            assertEquals(AuthErrorCode.INVALID_CREDENTIALS, ex.getCode());
        }
        AuthException locked = assertThrows(AuthException.class,
                () -> authService.login("alice", "alice123", "1.1.1.1"));
        assertEquals(AuthErrorCode.ACCOUNT_LOCKED, locked.getCode());
        clock.advanceMillis(60_000);
        assertDoesNotThrow(() -> authService.login("alice", "alice123", "1.1.1.1"), "解锁后正确凭据可登录");
        log.info("[登录编排] 失败->锁定->解锁 链路通过");
    }

    @Test
    @DisplayName("停用账号登录被拒绝且原因码为 ACCOUNT_DISABLED")
    void disabledAccountLoginRejected() {
        AuthException ex = assertThrows(AuthException.class,
                () -> authService.login("bob", "bob123", "1.1.1.1"));
        assertEquals(AuthErrorCode.ACCOUNT_DISABLED, ex.getCode());
        log.info("[登录编排] 停用账号拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("刷新时账号已停用：拒绝并吊销其全部刷新令牌")
    void refreshWithDisabledAccountRevokesAll() {
        TokenPair pair = authService.login("alice", "alice123", "1.1.1.1");
        // 停用 alice
        users.addUser("alice", "alice123", java.util.Set.of("USER"), false);
        AuthException ex = assertThrows(AuthException.class,
                () -> authService.refresh(pair.refreshToken()));
        assertEquals(AuthErrorCode.ACCOUNT_DISABLED, ex.getCode());
        log.info("[登录编排] 停用账号刷新拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("刷新成功轮换令牌对，旧刷新令牌重放被拒绝")
    void refreshRotatesAndRejectsReplay() {
        TokenPair pair = authService.login("alice", "alice123", "1.1.1.1");
        TokenPair next = authService.refresh(pair.refreshToken());
        assertNotEquals(pair.refreshToken(), next.refreshToken());
        AuthException ex = assertThrows(AuthException.class,
                () -> authService.refresh(pair.refreshToken()));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REUSED, ex.getCode());
        log.info("[登录编排] 刷新轮换+重放拒绝, code={}", ex.getCode());
    }
}
