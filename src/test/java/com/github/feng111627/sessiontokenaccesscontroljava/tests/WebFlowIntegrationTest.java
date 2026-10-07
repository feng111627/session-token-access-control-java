package com.github.feng111627.sessiontokenaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 业务域：Web 入口端到端（登录 -> 访问 -> 刷新 -> 重放 / 越权 / 锁定），
 * 验证各入口下错误结论一致且可区分。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebFlowIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebFlowIntegrationTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    private JsonNode login(String username, String password, String sourceIp) throws Exception {
        MvcResult res = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", sourceIp)
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();
        return MAPPER.readTree(res.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("完整链路：登录 -> 访问资源 -> 刷新 -> 旧刷新令牌重放被拒")
    void fullLoginRefreshReplayFlow(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        JsonNode tokens = login("alice", "alice123", "10.0.0.1");
        String access = tokens.get("accessToken").asText();
        String refresh = tokens.get("refreshToken").asText();

        mvc.perform(get("/api/resources/documents").param("action", "read")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.ruleVersion").value("v1"))
                .andExpect(jsonPath("$.subject").value("alice"));
        log.info("[Web链路] 访问资源 ALLOW");

        MvcResult refreshed = mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}".formatted(refresh)))
                .andExpect(status().isOk())
                .andReturn();
        String newRefresh = MAPPER.readTree(refreshed.getResponse().getContentAsString())
                .get("refreshToken").asText();
        assertNotEquals(refresh, newRefresh);
        log.info("[Web链路] 刷新轮换成功");

        mvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"%s\"}".formatted(refresh)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REUSED"));
        log.info("[Web链路] 旧刷新令牌重放 -> 401 REFRESH_TOKEN_REUSED");
    }

    @Test
    @DisplayName("未携带令牌访问受保护资源 -> 401 UNAUTHENTICATED")
    void missingToken(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        mvc.perform(get("/api/resources/documents"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        log.info("[Web链路] 未认证 -> 401 UNAUTHENTICATED");
    }

    @Test
    @DisplayName("篡改令牌访问 -> 401 TOKEN_TAMPERED")
    void tamperedToken(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        JsonNode tokens = login("alice", "alice123", "10.0.0.2");
        String access = tokens.get("accessToken").asText();
        String forged = access.substring(0, access.length() - 2)
                + (access.endsWith("AA") ? "BB" : "AA");
        mvc.perform(get("/api/resources/documents").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_TAMPERED"));
        log.info("[Web链路] 篡改令牌 -> 401 TOKEN_TAMPERED");
    }

    @Test
    @DisplayName("已认证但越权 -> 403 FORBIDDEN；资源不存在 -> 404 RESOURCE_NOT_FOUND")
    void forbiddenVsNotFound(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        JsonNode tokens = login("alice", "alice123", "10.0.0.3");
        String access = tokens.get("accessToken").asText();

        mvc.perform(get("/api/resources/admin-console")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        log.info("[Web链路] 越权 -> 403 FORBIDDEN");

        mvc.perform(get("/api/resources/ghost")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("RESOURCE_NOT_FOUND"));
        log.info("[Web链路] 资源不存在 -> 404 RESOURCE_NOT_FOUND");
    }

    @Test
    @DisplayName("停用账号登录 -> 403 ACCOUNT_DISABLED")
    void disabledAccount(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "10.0.0.4")
                        .content("{\"username\":\"bob\",\"password\":\"bob123\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
        log.info("[Web链路] 停用账号 -> 403 ACCOUNT_DISABLED");
    }

    @Test
    @DisplayName("连续失败达到阈值 -> 429 ACCOUNT_LOCKED，且正确口令也被拒")
    void lockoutAfterRepeatedFailures(TestInfo info) throws Exception {
        log.info("[Web链路] 用例: {}", info.getDisplayName());
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .header("X-Forwarded-For", "10.9.9.9")
                            .content("{\"username\":\"mallory\",\"password\":\"bad\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        }
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "10.9.9.9")
                        .content("{\"username\":\"mallory\",\"password\":\"mallory123\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
        log.info("[Web链路] 5 次失败后锁定 -> 429 ACCOUNT_LOCKED");
    }
}
