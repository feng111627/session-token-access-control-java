package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.LoginAttemptGuard;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务域：登录失败限流与临时锁定（按账号、按来源、自动解锁、并发一致）。
 */
class LoginAttemptGuardTest {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptGuardTest.class);
    private static final int MAX_FAILURES = 3;
    private static final long LOCK_MS = 60_000;
    private static final long T0 = 10_000_000;

    private MutableClock clock;
    private LoginAttemptGuard guard;

    @BeforeEach
    void setUp(TestInfo info) {
        clock = new MutableClock(T0);
        guard = new LoginAttemptGuard(MAX_FAILURES, LOCK_MS, clock);
        log.info("[限流锁定] 用例: {}", info.getDisplayName());
    }

    @Test
    @DisplayName("未达阈值不锁定，达到阈值立即锁定且解锁时间可预期")
    void locksAtThresholdWithPredictableUnlock() {
        guard.onFailure("alice", "1.1.1.1");
        guard.onFailure("alice", "1.1.1.1");
        assertDoesNotThrow(() -> guard.checkNotLocked("alice", "1.1.1.1"));
        guard.onFailure("alice", "1.1.1.1"); // 第 3 次失败触发锁定
        AuthException ex = assertThrows(AuthException.class,
                () -> guard.checkNotLocked("alice", "9.9.9.9")); // 换来源仍被账号维度锁定
        assertEquals(AuthErrorCode.ACCOUNT_LOCKED, ex.getCode());
        assertEquals(T0 + LOCK_MS, guard.lockedUntilEpochMs("alice", "9.9.9.9"));
        log.info("[限流锁定] 账号锁定, 解锁时刻={}", T0 + LOCK_MS);
    }

    @Test
    @DisplayName("锁定到期后自动解锁，无需人工干预")
    void autoUnlocksAfterLockDuration() {
        for (int i = 0; i < MAX_FAILURES; i++) guard.onFailure("alice", "1.1.1.1");
        assertThrows(AuthException.class, () -> guard.checkNotLocked("alice", "1.1.1.1"));
        clock.advanceMillis(LOCK_MS - 1);
        assertThrows(AuthException.class, () -> guard.checkNotLocked("alice", "1.1.1.1"), "差 1ms 仍锁定");
        clock.advanceMillis(1);
        assertDoesNotThrow(() -> guard.checkNotLocked("alice", "1.1.1.1"), "到期自动解锁");
        log.info("[限流锁定] 自动解锁于 T0+{}ms", LOCK_MS);
    }

    @Test
    @DisplayName("按来源维度独立锁定：同一来源连失败会锁定该来源下所有账号")
    void sourceLockAppliesToAllAccountsFromThatSource() {
        for (int i = 0; i < MAX_FAILURES; i++) guard.onFailure("user" + i, "6.6.6.6");
        AuthException ex = assertThrows(AuthException.class,
                () -> guard.checkNotLocked("someone-else", "6.6.6.6"));
        assertEquals(AuthErrorCode.SOURCE_LOCKED, ex.getCode());
        // 但其他来源不受影响
        assertDoesNotThrow(() -> guard.checkNotLocked("someone-else", "7.7.7.7"));
        log.info("[限流锁定] 来源锁定, code={}", ex.getCode());
    }

    @Test
    @DisplayName("登录成功清零计数，失败后重新累计")
    void successResetsCounters() {
        guard.onFailure("alice", "1.1.1.1");
        guard.onFailure("alice", "1.1.1.1");
        guard.onSuccess("alice", "1.1.1.1");
        guard.onFailure("alice", "1.1.1.1");
        guard.onFailure("alice", "1.1.1.1");
        assertDoesNotThrow(() -> guard.checkNotLocked("alice", "1.1.1.1"), "计数已复位，未达阈值");
        log.info("[限流锁定] 成功复位计数");
    }

    @Test
    @DisplayName("并发失败不会绕过限流：达到阈值后必锁定")
    void concurrentFailuresCannotBypassLock() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                go.await();
                guard.onFailure("alice", "1.1.1.1");
                return null;
            }));
        }
        go.countDown();
        for (Future<?> f : futures) f.get();
        pool.shutdown();
        AuthException ex = assertThrows(AuthException.class,
                () -> guard.checkNotLocked("alice", "1.1.1.1"));
        assertEquals(AuthErrorCode.ACCOUNT_LOCKED, ex.getCode());
        assertEquals(T0 + LOCK_MS, guard.lockedUntilEpochMs("alice", "1.1.1.1"));
        log.info("[限流锁定] 并发 {} 次失败后锁定成立", threads);
    }
}
