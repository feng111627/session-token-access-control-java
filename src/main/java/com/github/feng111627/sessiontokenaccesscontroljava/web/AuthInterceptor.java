package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.token.AccessTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 校验 Bearer 访问令牌，把解析出的声明放入请求属性。
 * 缺少令牌 -> UNAUTHENTICATED；令牌本身问题 -> TOKEN_MALFORMED/TAMPERED/EXPIRED。
 */
public class AuthInterceptor implements HandlerInterceptor {

    public static final String ATTR_CLAIMS = "auth.claims";

    private final AccessTokenService accessTokenService;

    public AuthInterceptor(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            throw new AuthException(AuthErrorCode.UNAUTHENTICATED, "missing Bearer access token");
        }
        AccessTokenClaims claims = accessTokenService.verify(header.substring("Bearer ".length()).trim());
        request.setAttribute(ATTR_CLAIMS, claims);
        return true;
    }
}
