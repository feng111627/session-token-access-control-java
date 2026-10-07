package com.github.feng111627.sessiontokenaccesscontroljava.auth;

import com.github.feng111627.sessiontokenaccesscontroljava.model.UserAccount;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存用户库：用户名 -> 账号（含加盐哈希后的口令）。
 */
public class UserDirectory {

    private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

    public UserDirectory() {
        // 预置演示账号：admin/admin123（ADMIN+USER）、alice/alice123（USER）、bob/bob123（USER，已停用）
        addUser("admin", "admin123", Set.of("ADMIN", "USER"), true);
        addUser("alice", "alice123", Set.of("USER"), true);
        addUser("bob", "bob123", Set.of("USER"), false);
        // 专供限流/锁定测试的账号，避免锁定影响其他演示账号
        addUser("mallory", "mallory123", Set.of("USER"), true);
    }

    public void addUser(String username, String rawPassword, Set<String> roles, boolean enabled) {
        users.put(username, new UserAccount(username, hash(rawPassword), Set.copyOf(roles), enabled));
    }

    public Optional<UserAccount> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public boolean verifyPassword(UserAccount account, String rawPassword) {
        byte[] expected = account.password().getBytes(StandardCharsets.UTF_8);
        byte[] actual = hash(rawPassword).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }

    static String hash(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // 固定演示盐，保证本地可复现；生产应使用随机盐与慢哈希
            byte[] digest = md.digest(("demo-salt:" + raw).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
