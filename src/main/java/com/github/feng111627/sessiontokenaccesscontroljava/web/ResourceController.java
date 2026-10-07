package com.github.feng111627.sessiontokenaccesscontroljava.web;

import com.github.feng111627.sessiontokenaccesscontroljava.auth.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 受保护的演示资源。鉴权由 {@link AuthFilter} 完成；
 * 资源不存在时返回 404，与 401/403 明确区分。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    private final Map<String, Map<String, Object>> documents = new ConcurrentHashMap<>();

    public ResourceController() {
        documents.put("doc-1", new LinkedHashMap<>(Map.of("id", "doc-1", "title", "Welcome", "owner", "alice")));
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<?> getDocument(@PathVariable String id,
                                         @RequestAttribute(AuthFilter.ATTR_TOKEN) TokenService.AccessToken token) {
        Map<String, Object> doc = documents.get(id);
        if (doc == null) {
            return ResponseEntity.status(404).body(Map.of("error", "RESOURCE_NOT_FOUND",
                    "message", "no document with id " + id));
        }
        return ResponseEntity.ok(doc);
    }

    @PostMapping("/documents")
    public ResponseEntity<?> createDocument(@RequestBody Map<String, String> body,
                                            @RequestAttribute(AuthFilter.ATTR_TOKEN) TokenService.AccessToken token) {
        String id = "doc-" + (documents.size() + 1);
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("id", id);
        doc.put("title", body.getOrDefault("title", "untitled"));
        doc.put("owner", token.subject());
        documents.put(id, doc);
        return ResponseEntity.status(201).body(doc);
    }

    @GetMapping("/admin/stats")
    public ResponseEntity<?> adminStats() {
        return ResponseEntity.ok(Map.of("documents", documents.size()));
    }
}
