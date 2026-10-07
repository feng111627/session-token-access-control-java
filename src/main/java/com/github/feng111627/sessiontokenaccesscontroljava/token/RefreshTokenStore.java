package com.github.feng111627.sessiontokenaccesscontroljava.token;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 刷新令牌的内存存储。
 * <p>轮换语义：每次 refresh 必须用当前 ACTIVE 的令牌换一个新令牌，旧令牌立即变为 ROTATED；
 * 再次提交 ROTATED/REVOKED 令牌会被识别为“已使用/已作废”并明确拒绝。
 * 所有状态变更在内部锁下完成，并发刷新不会产生两个有效新令牌。</p>
 */
public class RefreshTokenStore {

    private enum Status { ACTIVE, ROTATED, REVOKED }

    private record Record(String username, long expiresAtEpochMs, Status status) {
        Record withStatus(Status s) { return new Record(username, expiresAtEpochMs, s); }
    }

    private final long ttlMillis;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Record> tokens = new HashMap<>();
    private final Object lock = new Object();

    public RefreshTokenStore(long ttlMillis, Clock clock) {
        this.ttlMillis = ttlMillis;
        this.clock = clock;
    }

    public IssuedRefreshToken issue(String username) {
        synchronized (lock) {
            return issueLocked(username);
        }
    }

    /**
     * 轮换：校验旧令牌 -> 作废旧令牌 -> 签发新令牌，三步在同一临界区内完成。
     */
    public RotationResult rotate(String presentedToken) {
        synchronized (lock) {
            Record rec = tokens.get(presentedToken);
            if (rec == null) {
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_UNKNOWN, "refresh token not recognized");
            }
            switch (rec.status()) {
                case ROTATED -> throw new AuthException(AuthErrorCode.REFRESH_TOKEN_REUSED,
                        "refresh token was already rotated (possible replay)");
                case REVOKED -> throw new AuthException(AuthErrorCode.REFRESH_TOKEN_REUSED,
                        "refresh token was revoked");
                default -> { }
            }
            if (clock.millis() >= rec.expiresAtEpochMs()) {
                throw new AuthException(AuthErrorCode.REFRESH_TOKEN_EXPIRED,
                        "refresh token expired at " + rec.expiresAtEpochMs());
            }
            tokens.put(presentedToken, rec.withStatus(Status.ROTATED));
            IssuedRefreshToken next = issueLocked(rec.username());
            return new RotationResult(rec.username(), next.token(), next.expiresAtEpochMs());
        }
    }

    /** 账号被停用等场景下，吊销该用户的全部刷新令牌。 */
    public void revokeAllFor(String username) {
        synchronized (lock) {
            tokens.replaceAll((token, rec) ->
                    rec.username().equals(username) ? rec.withStatus(Status.REVOKED) : rec);
        }
    }

    private IssuedRefreshToken issueLocked(String username) {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        long expiresAt = clock.millis() + ttlMillis;
        tokens.put(token, new Record(username, expiresAt, Status.ACTIVE));
        return new IssuedRefreshToken(token, expiresAt);
    }

    public record IssuedRefreshToken(String token, long expiresAtEpochMs) {
    }

    public record RotationResult(String username, String newToken, long newExpiresAtEpochMs) {
    }
}
