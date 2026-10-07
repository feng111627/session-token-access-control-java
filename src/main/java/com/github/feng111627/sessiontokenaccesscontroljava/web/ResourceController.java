package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.access.AccessResult;
import com.github.feng111627.sessiontokenaccesscontroljava.access.AuthorizationService;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 受保护的资源入口：按 角色 + 资源范围 鉴权，
 * 未认证 / 越权 / 资源不存在 返回可区分的结论。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AuthorizationService authorizationService;

    public ResourceController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/{resource}")
    public Map<String, Object> access(@PathVariable String resource,
                                      @RequestParam(defaultValue = "read") String action,
                                      HttpServletRequest request) {
        AccessTokenClaims claims = (AccessTokenClaims) request.getAttribute(AuthInterceptor.ATTR_CLAIMS);
        AccessResult result = authorizationService.evaluate(claims, resource, action);
        switch (result.decision()) {
            case ALLOW -> {
                return Map.of(
                        "decision", "ALLOW",
                        "ruleVersion", result.ruleVersion(),
                        "resource", resource,
                        "action", action,
                        "subject", claims.subject());
            }
            case RESOURCE_NOT_FOUND ->
                    throw new AuthException(AuthErrorCode.RESOURCE_NOT_FOUND, result.detail());
            case FORBIDDEN ->
                    throw new AuthException(AuthErrorCode.FORBIDDEN, result.detail());
            default ->
                    throw new AuthException(AuthErrorCode.UNAUTHENTICATED, result.detail());
        }
    }
}
