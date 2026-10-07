package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.support.TimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 访问令牌服务：签发并校验 HMAC-SHA256 签名的紧凑型令牌。
 *
 * 格式：base64url(header).base64url(payload).base64url(signature)
 * payload 字段：sub(账号)、roles(逗号分隔)、type(access)、iat、exp。
 *
 * 校验失败时抛出携带具体 {@link TokenRejectionReason} 的 {@link AuthException}，
 * 调用方可以区分“被篡改 / 已过期 / 格式错误 / 类型用错”。
 */
@Service
public class TokenService {

    public static final String TYPE_ACCESS = "access";

    private final TimeProvider timeProvider;
    private final byte[] secret;
    private final long accessTokenTtlSeconds;

    public TokenService(TimeProvider timeProvider,
                        @Value("${security.token.secret:local-dev-secret-change-me}") String secret,
                        @Value("${security.token.access-ttl-seconds:300}") long accessTokenTtlSeconds) {
        this.timeProvider = timeProvider;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    /** 已解析并通过校验的访问令牌内容。 */
    public record AccessToken(String subject, java.util.Set<String> roles, long issuedAtEpochSeconds,
                              long expiresAtEpochSeconds) {
        public boolean hasRole(String role) {
            return roles.contains(role);
        }
    }

    /** 签发访问令牌。 */
    public String issueAccessToken(String subject, java.util.Set<String> roles) {
        long now = timeProvider.now().getEpochSecond();
        Map<String, String> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("sub", subject);
        payload.put("roles", String.join(",", roles));
        payload.put("type", TYPE_ACCESS);
        payload.put("iat", String.valueOf(now));
        payload.put("exp", String.valueOf(now + accessTokenTtlSeconds));

        String h = b64(encodeKv(header));
        String p = b64(encodeKv(payload));
        String sig = b64(sign(h + "." + p));
        return h + "." + p + "." + sig;
    }

    /**
     * 校验并解析访问令牌。
     *
     * @throws AuthException 携带 MALFORMED / TAMPERED / EXPIRED / WRONG_TOKEN_TYPE
     */
    public AccessToken verifyAccessToken(String token) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            throw new AuthException(TokenRejectionReason.MALFORMED, "token is not a three-part compact token");
        }
        byte[] expected = sign(parts[0] + "." + parts[1]);
        byte[] actual;
        try {
            actual = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new AuthException(TokenRejectionReason.MALFORMED, "signature is not valid base64url");
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new AuthException(TokenRejectionReason.TAMPERED, "signature mismatch");
        }
        Map<String, String> payload;
        try {
            payload = decodeKv(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new AuthException(TokenRejectionReason.MALFORMED, "payload is not valid base64url");
        }
        if (!TYPE_ACCESS.equals(payload.get("type"))) {
            throw new AuthException(TokenRejectionReason.WRONG_TOKEN_TYPE, "token type is not 'access'");
        }
        long exp = parseLong(payload.get("exp"), "exp");
        long iat = parseLong(payload.get("iat"), "iat");
        if (timeProvider.now().getEpochSecond() >= exp) {
            throw new AuthException(TokenRejectionReason.EXPIRED, "access token expired");
        }
        String sub = payload.get("sub");
        if (sub == null || sub.isBlank()) {
            throw new AuthException(TokenRejectionReason.MALFORMED, "missing subject");
        }
        java.util.Set<String> roles = new java.util.HashSet<>();
        String rolesStr = payload.get("roles");
        if (rolesStr != null && !rolesStr.isBlank()) {
            for (String r : rolesStr.split(",")) roles.add(r);
        }
        return new AccessToken(sub, java.util.Collections.unmodifiableSet(roles), iat, exp);
    }

    private long parseLong(String v, String field) {
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw new AuthException(TokenRejectionReason.MALFORMED, "field '" + field + "' is not a number");
        }
    }

    private byte[] sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign token", e);
        }
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String b64(String s) {
        return b64(s.getBytes(StandardCharsets.UTF_8));
    }

    /** 简单 key=value 编码（分号分隔），值中不允许出现分号与等号以外的转义需求。 */
    private static String encodeKv(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        map.forEach((k, v) -> {
            if (v.contains(";")) throw new IllegalArgumentException("value must not contain ';'");
            if (!sb.isEmpty()) sb.append(';');
            sb.append(k).append('=').append(v);
        });
        return sb.toString();
    }

    private static Map<String, String> decodeKv(String s) {
        Map<String, String> map = new LinkedHashMap<>();
        if (s.isEmpty()) return map;
        for (String pair : s.split(";")) {
            int idx = pair.indexOf('=');
            if (idx <= 0) throw new IllegalArgumentException("bad kv pair");
            map.put(pair.substring(0, idx), pair.substring(idx + 1));
        }
        return map;
    }
}
