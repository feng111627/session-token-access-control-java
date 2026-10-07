package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存用户库。预置三个演示账号：
 * <ul>
 *   <li>alice / alice-pass —— ROLE_USER</li>
 *   <li>bob / bob-pass —— ROLE_USER, ROLE_ADMIN</li>
 *   <li>carol / carol-pass —— ROLE_USER（默认停用，用于演示账号停用场景）</li>
 * </ul>
 */
@Component
public class UserStore {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserStore() {
        put("alice", "alice-pass", Set.of("ROLE_USER"), true);
        put("bob", "bob-pass", Set.of("ROLE_USER", "ROLE_ADMIN"), true);
        put("carol", "carol-pass", Set.of("ROLE_USER"), false);
    }

    private void put(String username, String password, Set<String> roles, boolean enabled) {
        byte[] saltBytes = new byte[16];
        new SecureRandom().nextBytes(saltBytes);
        String salt = HexFormat.of().formatHex(saltBytes);
        users.put(username, new UserAccount(username, salt, hash(salt, password), Set.copyOf(roles), enabled));
    }

    public Optional<UserAccount> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public boolean verifyPassword(UserAccount account, String password) {
        return MessageDigest.isEqual(
                HexFormat.of().parseHex(account.passwordHash()),
                HexFormat.of().parseHex(hash(account.salt(), password)));
    }

    /** 停用/启用账号（测试与管理入口使用）。 */
    public void setEnabled(String username, boolean enabled) {
        users.computeIfPresent(username, (k, v) -> v.withEnabled(enabled));
    }

    static String hash(String salt, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest((salt + ":" + password).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
