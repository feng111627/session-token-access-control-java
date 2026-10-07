package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 刷新令牌的内存存储，负责：
 * <ul>
 *   <li>签发不透明（opaque）刷新令牌，按账号归入一个“轮换家族”(family)</li>
 *   <li>刷新时强制轮换：旧令牌立即作废，返回新令牌</li>
 *   <li>重放检测：已轮换过的旧令牌再次被提交时，识别为 REUSED 并吊销整个家族</li>
 *   <li>过期、未知令牌分别识别为 EXPIRED / UNKNOWN_REFRESH_TOKEN</li>
 * </ul>
 * 所有状态变更在实例级锁内完成，并发刷新不会产生两个都有效的新令牌。
 */
@Component
public class RefreshTokenStore {

    private final TimeProvider timeProvider;
    private final long refreshTtlSeconds;
    private final SecureRandom random = new SecureRandom();

    private final Map<String, Record> byId = new ConcurrentHashMap<>();
    /** 每个账号当前有效的家族号；账号重新登录会开启新家族，旧家族整体失效。 */
    private final Map<String, Long> currentFamilyBySubject = new ConcurrentHashMap<>();

    public RefreshTokenStore(TimeProvider timeProvider,
                             @Value("${security.token.refresh-ttl-seconds:604800}") long refreshTtlSeconds) {
        this.timeProvider = timeProvider;
        this.refreshTtlSeconds = refreshTtlSeconds;
    }

    public long refreshTtlSeconds() {
        return refreshTtlSeconds;
    }

    private enum State { ACTIVE, ROTATED, REVOKED }

    private static final class Record {
        final String id;
        final String subject;
        final long family;
        final Instant expiresAt;
        State state;

        Record(String id, String subject, long family, Instant expiresAt) {
            this.id = id;
            this.subject = subject;
            this.family = family;
            this.expiresAt = expiresAt;
            this.state = State.ACTIVE;
        }
    }

    /** 轮换结果：新刷新令牌 + 所属账号。 */
    public record Rotation(String newRefreshToken, String subject) {}

    /** 登录成功后为账号签发全新家族的刷新令牌。 */
    public synchronized String issueFor(String subject) {
        long family = currentFamilyBySubject.merge(subject, 1L, Long::sum);
        revokeFamilyOf(subject, family); // 旧家族全部吊销
        return newToken(subject, family);
    }

    /**
     * 轮换刷新令牌。
     *
     * @throws AuthException REUSED（重放，家族被吊销）/ EXPIRED / UNKNOWN_REFRESH_TOKEN
     */
    public synchronized Rotation rotate(String presentedToken) {
        Record rec = byId.get(presentedToken);
        if (rec == null) {
            throw new AuthException(TokenRejectionReason.UNKNOWN_REFRESH_TOKEN,
                    "refresh token does not exist (revoked or never issued)");
        }
        if (rec.state == State.ROTATED) {
            // 重放：旧令牌被再次提交，视为泄露迹象，吊销整个家族
            revokeFamily(rec.family);
            throw new AuthException(TokenRejectionReason.REUSED,
                    "refresh token was already rotated; family revoked");
        }
        if (rec.state == State.REVOKED) {
            throw new AuthException(TokenRejectionReason.UNKNOWN_REFRESH_TOKEN,
                    "refresh token belongs to a revoked family");
        }
        if (!timeProvider.now().isBefore(rec.expiresAt)) {
            throw new AuthException(TokenRejectionReason.EXPIRED, "refresh token expired");
        }
        rec.state = State.ROTATED;
        return new Rotation(newToken(rec.subject, rec.family), rec.subject);
    }

    /** 吊销账号当前所有刷新令牌（如账号被停用、用户登出）。 */
    public synchronized void revokeAllFor(String subject) {
        Long family = currentFamilyBySubject.get(subject);
        if (family != null) revokeFamily(family);
    }

    private String newToken(String subject, long family) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byId.put(id, new Record(id, subject, family, timeProvider.now().plusSeconds(refreshTtlSeconds)));
        return id;
    }

    private void revokeFamilyOf(String subject, long exceptFamily) {
        byId.values().forEach(r -> {
            if (r.subject.equals(subject) && r.family != exceptFamily) r.state = State.REVOKED;
        });
    }

    private void revokeFamily(long family) {
        byId.values().forEach(r -> {
            if (r.family == family) r.state = State.REVOKED;
        });
    }
}
