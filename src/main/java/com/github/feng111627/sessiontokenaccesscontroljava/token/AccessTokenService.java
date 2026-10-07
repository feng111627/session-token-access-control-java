package com.github.feng111627.sessiontokenaccesscontroljava.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AccessTokenClaims;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthErrorCode;
import com.github.feng111627.sessiontokenaccesscontroljava.model.AuthException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * 访问令牌的签发与校验。
 * 格式：base64url(jsonPayload) + "." + base64url(hmacSha256(payload))。
 * 校验失败按 格式错误 / 篡改 / 过期 区分原因码。
 */
public class AccessTokenService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String HMAC_ALGO = "HmacSHA256";

    private final byte[] secret;
    private final long ttlMillis;
    private final Clock clock;

    public AccessTokenService(String secret, long ttlMillis, Clock clock) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.ttlMillis = ttlMillis;
        this.clock = clock;
    }

    public String issue(String subject, Set<String> roles) {
        long now = clock.millis();
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("sub", subject);
        payload.put("iat", now);
        payload.put("exp", now + ttlMillis);
        payload.put("jti", UUID.randomUUID().toString());
        var rolesNode = payload.putArray("roles");
        roles.forEach(rolesNode::add);
        String payloadB64 = base64Url(payload.toString().getBytes(StandardCharsets.UTF_8));
        String sigB64 = base64Url(sign(payloadB64));
        return payloadB64 + "." + sigB64;
    }

    public AccessTokenClaims verify(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthException(AuthErrorCode.TOKEN_MALFORMED, "token is empty");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new AuthException(AuthErrorCode.TOKEN_MALFORMED, "token must be <payload>.<signature>");
        }
        byte[] expectedSig = sign(parts[0]);
        byte[] actualSig;
        try {
            actualSig = base64UrlDecode(parts[1]);
        } catch (IllegalArgumentException e) {
            throw new AuthException(AuthErrorCode.TOKEN_MALFORMED, "signature is not valid base64url");
        }
        if (!MessageDigest.isEqual(expectedSig, actualSig)) {
            throw new AuthException(AuthErrorCode.TOKEN_TAMPERED, "signature mismatch");
        }
        JsonNode payload;
        try {
            payload = MAPPER.readTree(base64UrlDecode(parts[0]));
        } catch (Exception e) {
            throw new AuthException(AuthErrorCode.TOKEN_MALFORMED, "payload is not valid JSON");
        }
        JsonNode sub = payload.get("sub");
        JsonNode iat = payload.get("iat");
        JsonNode exp = payload.get("exp");
        JsonNode jti = payload.get("jti");
        if (sub == null || !sub.isTextual() || exp == null || !exp.isNumber()
                || iat == null || !iat.isNumber() || jti == null || !jti.isTextual()) {
            throw new AuthException(AuthErrorCode.TOKEN_MALFORMED, "payload misses required claims");
        }
        long expiresAt = exp.asLong();
        if (clock.millis() >= expiresAt) {
            throw new AuthException(AuthErrorCode.TOKEN_EXPIRED, "token expired at " + expiresAt);
        }
        Set<String> roles = new LinkedHashSet<>();
        JsonNode rolesNode = payload.get("roles");
        if (rolesNode != null && rolesNode.isArray()) {
            rolesNode.forEach(r -> { if (r.isTextual()) roles.add(r.asText()); });
        }
        return new AccessTokenClaims(sub.asText(), roles, iat.asLong(), expiresAt, jti.asText());
    }

    private byte[] sign(String payloadB64) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(secret, HMAC_ALGO));
            return mac.doFinal(payloadB64.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign token", e);
        }
    }

    private static String base64Url(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] base64UrlDecode(String s) {
        return java.util.Base64.getUrlDecoder().decode(s);
    }
}
