package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.RefreshTokenStore;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenRejectionReason;
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

@DisplayName("刷新令牌：轮换、重放检测、过期、并发")
class RefreshTokenStoreTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenStoreTest.class);

    private MutableClock clock;
    private RefreshTokenStore store;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        store = new RefreshTokenStore(clock, 604800);
    }

    @Test
    @DisplayName("轮换：旧令牌作废，新令牌可用")
    void rotationInvalidatesOldToken() {
        log.info("CASE 正常轮换: 旧令牌被消费, 期望再次提交旧令牌=REUSED");
        String t1 = store.issueFor("alice");
        RefreshTokenStore.Rotation r = store.rotate(t1);
        assertEquals("alice", r.subject());
        assertNotEquals(t1, r.newRefreshToken());
        // 旧令牌再次提交 → 重放
        AuthException e = assertThrows(AuthException.class, () -> store.rotate(t1));
        assertEquals(TokenRejectionReason.REUSED, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("重放：旧令牌被再次提交时整个家族被吊销，新令牌也随之失效")
    void replayRevokesWholeFamily() {
        log.info("CASE 重放检测: 重放 t1 后, 期望家族内合法的新令牌 t2 也被吊销");
        String t1 = store.issueFor("alice");
        String t2 = store.rotate(t1).newRefreshToken();
        // 攻击者重放 t1 → 家族吊销
        assertThrows(AuthException.class, () -> store.rotate(t1));
        // 合法用户持有的 t2 也失效，且原因不是 REUSED 而是 UNKNOWN（家族已吊销）
        AuthException e = assertThrows(AuthException.class, () -> store.rotate(t2));
        assertEquals(TokenRejectionReason.UNKNOWN_REFRESH_TOKEN, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("过期：刷新令牌过期后被拒绝，原因=EXPIRED")
    void expiredRefreshTokenRejected() {
        log.info("CASE 刷新令牌过期: 时钟推进 7 天+1s, 期望 EXPIRED");
        String t1 = store.issueFor("alice");
        clock.advanceSeconds(604800 + 1);
        AuthException e = assertThrows(AuthException.class, () -> store.rotate(t1));
        assertEquals(TokenRejectionReason.EXPIRED, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("未知令牌：从未签发的令牌被拒绝，原因=UNKNOWN_REFRESH_TOKEN")
    void unknownTokenRejected() {
        log.info("CASE 未知刷新令牌: 期望 UNKNOWN_REFRESH_TOKEN");
        AuthException e = assertThrows(AuthException.class, () -> store.rotate("does-not-exist"));
        assertEquals(TokenRejectionReason.UNKNOWN_REFRESH_TOKEN, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("重新登录：开启新家族，旧家族令牌全部失效")
    void reloginRevokesPreviousFamily() {
        log.info("CASE 重新登录: 旧家族令牌期望 UNKNOWN_REFRESH_TOKEN");
        String t1 = store.issueFor("alice");
        store.issueFor("alice"); // 重新登录
        AuthException e = assertThrows(AuthException.class, () -> store.rotate(t1));
        assertEquals(TokenRejectionReason.UNKNOWN_REFRESH_TOKEN, e.tokenRejectionReason());
    }

    @Test
    @DisplayName("并发轮换：同一令牌并发提交，只有一个成功，其余为重放")
    void concurrentRotationYieldsSingleWinner() throws Exception {
        log.info("CASE 并发刷新: 16 线程同时提交同一令牌, 期望恰好 1 个成功, 其余 TOKEN_REJECTED");
        String t1 = store.issueFor("alice");
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
                    store.rotate(t1);
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
        assertEquals(1, successes, "并发轮换必须恰好一个成功");
    }
}
