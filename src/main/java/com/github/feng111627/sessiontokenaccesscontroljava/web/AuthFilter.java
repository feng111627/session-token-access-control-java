package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.AuthException;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenRejectionReason;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenService;
import com.github.feng111627.sessiontokenaccesscontroljava.auth.UserStore;
import com.github.feng111627.sessiontokenaccesscontroljava.authz.AuthorizationService;
import com.github.feng111627.sessiontokenaccesscontroljava.authz.DecisionRecord;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 保护 /api/** 的过滤器。三种结论严格区分：
 * <ul>
 *   <li>401 UNAUTHENTICATED —— 无令牌或令牌被拒绝（附具体 tokenRejectionReason）</li>
 *   <li>403 FORBIDDEN —— 已认证但越权（附命中的规则与策略版本）</li>
 *   <li>404 —— 由控制器在资源不存在时返回（本过滤器不拦截存在性判断）</li>
 * </ul>
 */
@Component
public class AuthFilter extends OncePerRequestFilter {

    public static final String ATTR_TOKEN = "verifiedAccessToken";

    private final TokenService tokenService;
    private final UserStore userStore;
    private final AuthorizationService authorizationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AuthFilter(TokenService tokenService, UserStore userStore, AuthorizationService authorizationService) {
        this.tokenService = tokenService;
        this.userStore = userStore;
        this.authorizationService = authorizationService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String scope = scopeOf(request.getMethod());

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            authorizationService.denyUnauthenticated(path, scope, "missing Bearer token");
            writeError(response, 401, "UNAUTHENTICATED", "missing Bearer token", null);
            return;
        }
        TokenService.AccessToken token;
        try {
            token = tokenService.verifyAccessToken(header.substring(7));
        } catch (AuthException e) {
            TokenRejectionReason reason = e.tokenRejectionReason();
            authorizationService.denyUnauthenticated(path, scope, "token rejected: " + reason);
            writeError(response, 401, "UNAUTHENTICATED", e.getMessage(), reason.name());
            return;
        }
        // 账号被停用后，已签发且未过期的访问令牌也必须立即失效
        boolean enabled = userStore.find(token.subject()).map(u -> u.enabled()).orElse(false);
        if (!enabled) {
            authorizationService.denyUnauthenticated(path, scope, "account disabled");
            writeError(response, 401, "UNAUTHENTICATED", "account is disabled",
                    TokenRejectionReason.ACCOUNT_DISABLED.name());
            return;
        }
        DecisionRecord decision = authorizationService.authorize(token, path, scope);
        if (decision.outcome() != DecisionRecord.Outcome.PERMITTED) {
            writeForbidden(response, decision);
            return;
        }
        request.setAttribute(ATTR_TOKEN, token);
        chain.doFilter(request, response);
    }

    static String scopeOf(String method) {
        return "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method) ? "read" : "write";
    }

    private void writeForbidden(HttpServletResponse response, DecisionRecord d) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "FORBIDDEN");
        body.put("message", d.reason());
        body.put("policyVersion", d.policyVersion());
        body.put("ruleId", d.ruleId());
        body.put("decisionId", d.sequence());
        response.setStatus(403);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }

    private void writeError(HttpServletResponse response, int status, String code, String message, String reason)
            throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("message", message);
        if (reason != null) body.put("tokenRejectionReason", reason);
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
