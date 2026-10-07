package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.token.RefreshTokenStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 业务域：刷新令牌轮换与重放保护。
 */
class RefreshTokenStoreTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenStoreTest.class);
    private static final long TTL = 300_000;

    private MutableClock clock;
    private RefreshTokenStore store;

    @BeforeEach
    void setUp(TestInfo info) {
        clock = new MutableClock(5_000_000);
        store = new RefreshTokenStore(TTL, clock);
        log.info("[刷新令牌] 用例: {}", info.getDisplayName());
    }

    @Test
    @DisplayName("轮换后旧令牌作废、新令牌可用")
    void rotationInvalidatesOldToken() {
        var issued = store.issue("alice");
        var rotated = store.rotate(issued.token());
        assertEquals("alice", rotated.username());
        assertNotEquals(issued.token(), rotated.newToken());
        // 新令牌还能继续轮换
        var again = store.rotate(rotated.newToken());
        assertEquals("alice", again.username());
        log.info("[刷新令牌] 连续轮换成功");
    }

    @Test
    @DisplayName("已轮换的旧令牌再次提交被识别为 REFRESH_TOKEN_REUSED")
    void replayedTokenRejected() {
        var issued = store.issue("alice");
        store.rotate(issued.token());
        AuthException ex = assertThrows(AuthException.class, () -> store.rotate(issued.token()));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REUSED, ex.getCode());
        log.info("[刷新令牌] 重放拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("未知令牌被拒绝且原因码为 REFRESH_TOKEN_UNKNOWN")
    void unknownTokenRejected() {
        AuthException ex = assertThrows(AuthException.class, () -> store.rotate("no-such-token"));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, ex.getCode());
        log.info("[刷新令牌] 未知令牌拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("过期刷新令牌被拒绝且原因码为 REFRESH_TOKEN_EXPIRED")
    void expiredTokenRejected() {
        var issued = store.issue("alice");
        clock.advanceMillis(TTL);
        AuthException ex = assertThrows(AuthException.class, () -> store.rotate(issued.token()));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_EXPIRED, ex.getCode());
        log.info("[刷新令牌] 过期拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("吊销后令牌被拒绝")
    void revokedTokenRejected() {
        var issued = store.issue("alice");
        store.revokeAllFor("alice");
        AuthException ex = assertThrows(AuthException.class, () -> store.rotate(issued.token()));
        assertEquals(AuthErrorCode.REFRESH_TOKEN_REUSED, ex.getCode());
        log.info("[刷新令牌] 吊销拒绝, code={}", ex.getCode());
    }

    @Test
    @DisplayName("并发提交同一刷新令牌：恰好一个成功，其余全部判定为重放")
    void concurrentRotationYieldsSingleWinner() throws Exception {
        var issued = store.issue("alice");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Callable<String>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                ready.countDown();
                go.await();
                try {
                    return "OK:" + store.rotate(issued.token()).newToken();
                } catch (AuthException e) {
                    return "ERR:" + e.getCode();
                }
            });
        }
        List<Future<String>> futures = new ArrayList<>();
        for (Callable<String> t : tasks) futures.add(pool.submit(t));
        ready.await();
        go.countDown();
        List<String> results = new ArrayList<>();
        for (Future<String> f : futures) results.add(f.get());
        pool.shutdown();

        long ok = results.stream().filter(r -> r.startsWith("OK")).count();
        long reused = results.stream().filter(r -> r.equals("ERR:" + AuthErrorCode.REFRESH_TOKEN_REUSED)).count();
        assertEquals(1, ok, "恰好一个并发请求能轮换成功");
        assertEquals(threads - 1, reused, "其余全部识别为重放");
        log.info("[刷新令牌] 并发轮换: 成功={}, 重放拒绝={}", ok, reused);
    }
}
