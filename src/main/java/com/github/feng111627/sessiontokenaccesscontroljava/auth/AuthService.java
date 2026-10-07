package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import org.springframework.stereotype.Service;

/**
 * 认证编排：登录（限流/锁定 → 校验凭据 → 颁发令牌对）与刷新（轮换 + 账号状态复核）。
 */
@Service
public class AuthService {

    private final UserStore userStore;
    private final LoginAttemptLimiter limiter;
    private final TokenService tokenService;
    private final RefreshTokenStore refreshTokenStore;

    public AuthService(UserStore userStore, LoginAttemptLimiter limiter,
                       TokenService tokenService, RefreshTokenStore refreshTokenStore) {
        this.userStore = userStore;
        this.limiter = limiter;
        this.tokenService = tokenService;
        this.refreshTokenStore = refreshTokenStore;
    }

    /** 登录成功后颁发的一对令牌。 */
    public record TokenPair(String accessToken, String refreshToken,
                            long accessExpiresInSeconds, long refreshExpiresInSeconds) {}

    /**
     * 登录。
     *
     * @param source 来源标识（通常为客户端 IP）
     * @throws AuthException ACCOUNT_LOCKED / RATE_LIMITED / BAD_CREDENTIALS / ACCOUNT_DISABLED
     */
    public TokenPair login(String username, String password, String source) {
        UserAccount account = userStore.find(username).orElse(null);
        // 检查锁定/限流、验证凭据、计数/清零在同一原子步骤内完成
        boolean ok = limiter.attempt(username, source,
                () -> account != null && userStore.verifyPassword(account, password));
        if (!ok) {
            throw new AuthException(AuthException.Kind.BAD_CREDENTIALS, "bad username or password");
        }
        if (!account.enabled()) {
            throw new AuthException(AuthException.Kind.ACCOUNT_DISABLED, "account is disabled");
        }
        return issuePair(account);
    }

    /**
     * 刷新：轮换刷新令牌并复核账号状态。
     *
     * @throws AuthException TOKEN_REJECTED（REUSED/EXPIRED/UNKNOWN_REFRESH_TOKEN）/ ACCOUNT_DISABLED
     */
    public TokenPair refresh(String presentedRefreshToken) {
        RefreshTokenStore.Rotation rotation = refreshTokenStore.rotate(presentedRefreshToken);
        UserAccount account = userStore.find(rotation.subject())
                .filter(UserAccount::enabled)
                .orElseThrow(() -> {
                    // 账号已被停用：吊销其全部刷新令牌，拒绝本次刷新
                    refreshTokenStore.revokeAllFor(rotation.subject());
                    return new AuthException(AuthException.Kind.ACCOUNT_DISABLED, "account is disabled");
                });
        // 直接使用轮换产生的新刷新令牌；若重新 issueFor 会开启新家族并吊销刚轮换的令牌
        String access = tokenService.issueAccessToken(account.username(), account.roles());
        return new TokenPair(access, rotation.newRefreshToken(),
                tokenService.accessTokenTtlSeconds(), refreshTokenStore.refreshTtlSeconds());
    }

    /** 登出/停用账号时吊销其全部刷新令牌。 */
    public void logout(String username) {
        refreshTokenStore.revokeAllFor(username);
    }

    private TokenPair issuePair(UserAccount account) {
        String access = tokenService.issueAccessToken(account.username(), account.roles());
        String refresh = refreshTokenStore.issueFor(account.username());
        return new TokenPair(access, refresh,
                tokenService.accessTokenTtlSeconds(), refreshTokenStore.refreshTtlSeconds());
    }
}
