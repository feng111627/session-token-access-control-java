package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.*;
import com.github.feng111627.sessiontokenaccesscontroljava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("登录与刷新编排：限流、锁定、自动解锁、账号停用、并发")
class AuthServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceTest.class);

    private static final int MAX_FAILURES = 3;
    private static final long LOCK_SECONDS = 300;

    private MutableClock clock;
    private UserStore userStore;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        userStore = new UserStore();
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(clock, MAX_FAILURES, 20, 600, LOCK_SECONDS);
        TokenService tokenService = new TokenService(clock, "test-secret", 300);
        RefreshTokenStore refreshStore = new RefreshTokenStore(clock, 604800);
        authService = new AuthService(userStore, limiter, tokenService, refreshStore);
    }

    @Test
    @DisplayName("登录成功：颁发访问+刷新令牌对")
    void loginSuccess() {
        log.info("CASE 登录成功: alice 正确口令, 期望返回令牌对");
        AuthService.TokenPair pair = authService.login("alice", "alice-pass", "10.0.0.1");
        assertNotNull(pair.accessToken());
        assertNotNull(pair.refreshToken());
        assertEquals(300, pair.accessExpiresInSeconds());
    }

    @Test
    @DisplayName("连续失败达到阈值后账号被锁定，锁定时长可预期")
    void lockAfterThreshold() {
        log.info("CASE 账号锁定: 连续 {} 次失败, 期望第 {} 次起 ACCOUNT_LOCKED 且 retryAfter≈{}s",
                MAX_FAILURES, MAX_FAILURES + 1, LOCK_SECONDS);
        for (int i = 0; i < MAX_FAILURES; i++) {
            AuthException e = assertThrows(AuthException.class,
                    () -> authService.login("alice", "wrong", "10.0.0.1"));
            assertEquals(AuthException.Kind.BAD_CREDENTIALS, e.kind());
        }
        AuthException locked = assertThrows(AuthException.class,
                () -> authService.login("alice", "alice-pass", "10.0.0.1"));
        assertEquals(AuthException.Kind.ACCOUNT_LOCKED, locked.kind());
        assertNotNull(locked.retryAfterSeconds());
        assertTrue(locked.retryAfterSeconds() <= LOCK_SECONDS && locked.retryAfterSeconds() > LOCK_SECONDS - 5,
                "retryAfter 应接近锁定时长: " + locked.retryAfterSeconds());
    }

    @Test
    @DisplayName("锁定到期后自动解锁，正确口令可登录")
    void autoUnlockAfterLockDuration() {
        log.info("CASE 自动解锁: 时钟推进 {}s, 期望锁定解除", LOCK_SECONDS);
        for (int i = 0; i < MAX_FAILURES; i++) {
            assertThrows(AuthException.class, () -> authService.login("alice", "wrong", "10.0.0.1"));
        }
        assertThrows(AuthException.class, () -> authService.login("alice", "alice-pass", "10.0.0.1"));
        clock.advanceSeconds(LOCK_SECONDS + 1);
        AuthService.TokenPair pair = authService.login("alice", "alice-pass", "10.0.0.1");
        assertNotNull(pair.accessToken());
    }

    @Test
    @DisplayName("登录成功清零失败计数：失败 N-1 次后成功，再失败不会立即锁定")
    void successResetsCounter() {
        log.info("CASE 成功清零计数: 失败 {} 次→成功→再失败 {} 次, 期望仍不锁定", MAX_FAILURES - 1, MAX_FAILURES - 1);
        for (int i = 0; i < MAX_FAILURES - 1; i++) {
            assertThrows(AuthException.class, () -> authService.login("alice", "wrong", "10.0.0.1"));
        }
        authService.login("alice", "alice-pass", "10.0.0.1");
        for (int i = 0; i < MAX_FAILURES - 1; i++) {
            AuthException e = assertThrows(AuthException.class,
                    () -> authService.login("alice", "wrong", "10.0.0.1"));
            assertEquals(AuthException.Kind.BAD_CREDENTIALS, e.kind());
        }
    }

    @Test
    @DisplayName("按来源限流：同一来源对多账号累计失败达阈值后被限流")
    void perSourceRateLimit() {
        log.info("CASE 来源限流: 同一 IP 对不同账号累计 20 次失败, 期望 RATE_LIMITED");
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(clock, 100, 5, 600, LOCK_SECONDS);
        AuthService svc = new AuthService(userStore, limiter,
                new TokenService(clock, "s", 300), new RefreshTokenStore(clock, 1000));
        for (int i = 0; i < 5; i++) {
            String username = "user" + i;
            assertThrows(AuthException.class,
                    () -> svc.login(username, "wrong", "10.9.9.9"));
        }
        AuthException e = assertThrows(AuthException.class,
                () -> svc.login("alice", "alice-pass", "10.9.9.9"));
        assertEquals(AuthException.Kind.RATE_LIMITED, e.kind());
        assertNotNull(e.retryAfterSeconds());
    }

    @Test
    @DisplayName("停用账号：登录被拒（ACCOUNT_DISABLED），刷新也被拒且令牌吊销")
    void disabledAccountRejectedEverywhere() {
        log.info("CASE 账号停用: carol 默认停用, 期望登录 ACCOUNT_DISABLED; alice 停用后期望刷新失败");
        AuthException e = assertThrows(AuthException.class,
                () -> authService.login("carol", "carol-pass", "10.0.0.1"));
        assertEquals(AuthException.Kind.ACCOUNT_DISABLED, e.kind());

        AuthService.TokenPair pair = authService.login("alice", "alice-pass", "10.0.0.1");
        userStore.setEnabled("alice", false);
        AuthException refreshError = assertThrows(AuthException.class,
                () -> authService.refresh(pair.refreshToken()));
        assertEquals(AuthException.Kind.ACCOUNT_DISABLED, refreshError.kind());
    }

    @Test
    @DisplayName("并发登录：并发失败不会绕过锁定阈值")
    void concurrentLoginsCannotBypassLock() throws Exception {
        log.info("CASE 并发登录: 32 线程同时用错误口令, 期望锁定后其余请求均为 ACCOUNT_LOCKED 而非 BAD_CREDENTIALS");
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<AuthException.Kind>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                try {
                    authService.login("alice", "wrong", "10.0.0.1");
                    return null;
                } catch (AuthException e) {
                    return e.kind();
                }
            }));
        }
        ready.await();
        go.countDown();
        int badCredentials = 0, locked = 0;
        for (Future<AuthException.Kind> f : futures) {
            AuthException.Kind kind = f.get();
            if (kind == AuthException.Kind.BAD_CREDENTIALS) badCredentials++;
            else if (kind == AuthException.Kind.ACCOUNT_LOCKED) locked++;
        }
        pool.shutdown();
        log.info("CASE 并发登录结果: BAD_CREDENTIALS={}, ACCOUNT_LOCKED={}", badCredentials, locked);
        assertEquals(threads, badCredentials + locked, "所有请求都必须被计数或被锁定拦截");
        assertTrue(badCredentials <= MAX_FAILURES + 1,
                "进入计数的失败不应显著超过阈值: " + badCredentials);
        assertTrue(locked > 0, "并发下必须出现锁定拦截");
    }

    @Test
    @DisplayName("并发刷新：同一刷新令牌并发提交，只有一个能换到新令牌")
    void concurrentRefreshSingleWinner() throws Exception {
        log.info("CASE 并发刷新(编排层): 16 线程同时刷新, 期望恰好 1 个成功");
        AuthService.TokenPair pair = authService.login("alice", "alice-pass", "10.0.0.1");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                try {
                    authService.refresh(pair.refreshToken());
                    return true;
                } catch (AuthException e) {
                    return false;
                }
            }));
        }
        ready.await();
        go.countDown();
        int successes = 0;
        for (Future<Boolean> f : futures) if (f.get()) successes++;
        pool.shutdown();
        assertEquals(1, successes);
    }
}
