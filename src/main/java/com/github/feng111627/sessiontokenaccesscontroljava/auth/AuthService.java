package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.model.TokenPair;
import com.github.feng111627.sessiontokenaccesscontroljava.model.UserAccount;
import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.token.RefreshTokenStore;

/**
 * 登录与刷新编排。
 * <p>登录顺序：锁定检查 -> 账号存在性 -> 账号启用状态 -> 口令校验 -> 计数复位 -> 颁发令牌对。
 * 刷新顺序：轮换刷新令牌（识别重放/过期/未知）-> 账号启用状态检查（停用时吊销全部令牌）。</p>
 */
public class AuthService {

    private final UserDirectory users;
    private final LoginAttemptGuard guard;
    private final AccessTokenService accessTokens;
    private final RefreshTokenStore refreshTokens;

    public AuthService(UserDirectory users, LoginAttemptGuard guard,
                       AccessTokenService accessTokens, RefreshTokenStore refreshTokens) {
        this.users = users;
        this.guard = guard;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
    }

    public TokenPair login(String username, String password, String source) {
        guard.checkNotLocked(username, source);
        UserAccount account = users.find(username).orElse(null);
        if (account == null) {
            guard.onFailure(username, source);
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS, "unknown username or bad password");
        }
        if (!account.enabled()) {
            throw new AuthException(AuthErrorCode.ACCOUNT_DISABLED, "account is disabled");
        }
        if (!users.verifyPassword(account, password)) {
            guard.onFailure(username, source);
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS, "unknown username or bad password");
        }
        guard.onSuccess(username, source);
        return issuePair(account);
    }

    public TokenPair refresh(String refreshToken) {
        RefreshTokenStore.RotationResult rotation = refreshTokens.rotate(refreshToken);
        UserAccount account = users.find(rotation.username())
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CREDENTIALS, "account no longer exists"));
        if (!account.enabled()) {
            refreshTokens.revokeAllFor(account.username());
            throw new AuthException(AuthErrorCode.ACCOUNT_DISABLED, "account is disabled");
        }
        String accessToken = accessTokens.issue(account.username(), account.roles());
        return new TokenPair(accessToken, rotation.newToken(),
                accessTokens.verify(accessToken).expiresAtEpochMs(), rotation.newExpiresAtEpochMs());
    }

    private TokenPair issuePair(UserAccount account) {
        String accessToken = accessTokens.issue(account.username(), account.roles());
        RefreshTokenStore.IssuedRefreshToken refreshToken = refreshTokens.issue(account.username());
        return new TokenPair(accessToken, refreshToken.token(),
                accessTokens.verify(accessToken).expiresAtEpochMs(), refreshToken.expiresAtEpochMs());
    }
}
