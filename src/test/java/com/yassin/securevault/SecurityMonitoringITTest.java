package com.yassin.securevault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yassin.securevault.entity.Role;
import com.yassin.securevault.entity.User;
import com.yassin.securevault.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityMonitoringITTest extends BaseIntegrationTest {

    @LocalServerPort
    int port;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    private final ObjectMapper om = new ObjectMapper();
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void cross_user_reveal_attempt_increases_risk_and_creates_incident() throws Exception {
        long nonce = Instant.now().toEpochMilli();
        String userAEmail = "sec-a+" + nonce + "@test.com";
        String userBEmail = "sec-b+" + nonce + "@test.com";
        String adminEmail = "admin+" + nonce + "@test.com";
        String password = "Password123!";

        ensureAdminUser(adminEmail, password);
        register(userAEmail, password);
        register(userBEmail, password);

        String tokenA = login(userAEmail, password, null);
        String tokenB = login(userBEmail, password, null);
        String tokenAdmin = login(adminEmail, password, null);

        Long secretId = createSecret(tokenA, "t-" + nonce, "plain-" + nonce);

        HttpResponse<String> revealByB = get("/api/secrets/" + secretId + "/reveal", tokenB, null);
        assertThat(revealByB.statusCode()).isEqualTo(404);

        HttpResponse<String> topRiskRes = get("/api/security/risk/top?window=24h&limit=20", tokenAdmin, null);
        assertThat(topRiskRes.statusCode()).isEqualTo(200);
        List<?> topRisks = om.readValue(topRiskRes.body(), List.class);
        assertThat(topRisks.toString()).contains(userBEmail);
        assertThat(topRisks.toString()).contains("FORBIDDEN_OR_ENUM");

        HttpResponse<String> incidentsRes = get("/api/security/incidents?page=0&size=50", tokenAdmin, null);
        assertThat(incidentsRes.statusCode()).isEqualTo(200);
        Map<?, ?> incidentsBody = om.readValue(incidentsRes.body(), Map.class);
        assertThat(incidentsBody.get("content").toString()).contains("CROSS_USER_SECRET_ACCESS_ATTEMPT");
    }

    @Test
    void brute_force_attempt_triggers_rate_limit_and_high_risk() throws Exception {
        long nonce = Instant.now().toEpochMilli();
        String userEmail = "brute+" + nonce + "@test.com";
        String adminEmail = "admin2+" + nonce + "@test.com";
        String password = "Password123!";
        String sourceIp = "203.0.113.77";

        ensureAdminUser(adminEmail, password);
        register(userEmail, password);
        String tokenAdmin = login(adminEmail, password, null);

        int tooManyRequests = 0;
        for (int i = 0; i < 8; i++) {
            HttpResponse<String> res = post("/auth/login", null, Map.of(
                    "email", userEmail,
                    "password", "WrongPassword123!"
            ), sourceIp);
            if (res.statusCode() == 429) {
                tooManyRequests++;
            }
        }
        assertThat(tooManyRequests).isGreaterThan(0);

        HttpResponse<String> overviewRes = get("/api/security/overview", tokenAdmin, null);
        assertThat(overviewRes.statusCode()).isEqualTo(200);
        Map<?, ?> overview = om.readValue(overviewRes.body(), Map.class);
        assertThat(((Number) overview.get("rateLimitsLast24h")).longValue()).isGreaterThan(0);

        HttpResponse<String> topRiskRes = get("/api/security/risk/top?window=24h&limit=20", tokenAdmin, null);
        assertThat(topRiskRes.statusCode()).isEqualTo(200);
        assertThat(topRiskRes.body()).contains(sourceIp);
    }

    @Test
    void normal_behavior_does_not_create_high_incident_for_user() throws Exception {
        long nonce = Instant.now().toEpochMilli();
        String userEmail = "normal+" + nonce + "@test.com";
        String adminEmail = "admin3+" + nonce + "@test.com";
        String password = "Password123!";

        ensureAdminUser(adminEmail, password);
        register(userEmail, password);

        String userToken = login(userEmail, password, null);
        String adminToken = login(adminEmail, password, null);

        Long secretId = createSecret(userToken, "normal-title-" + nonce, "safe-data-" + nonce);
        HttpResponse<String> reveal = get("/api/secrets/" + secretId + "/reveal", userToken, null);
        assertThat(reveal.statusCode()).isEqualTo(200);

        HttpResponse<String> anomaliesRes = get("/api/security/anomalies?page=0&size=100", adminToken, null);
        assertThat(anomaliesRes.statusCode()).isEqualTo(200);
        Map<?, ?> anomalies = om.readValue(anomaliesRes.body(), Map.class);
        String content = String.valueOf(anomalies.get("content"));
        assertThat(content).doesNotContain(userEmail + ", severity=HIGH");
        assertThat(content).doesNotContain("subjectValue=" + userEmail + ", severity=HIGH");
    }

    private void ensureAdminUser(String email, String password) {
        userRepository.findByEmail(email).orElseGet(() -> userRepository.save(
                User.builder()
                        .email(email)
                        .passwordHash(passwordEncoder.encode(password))
                        .role(Role.ADMIN)
                        .build()
        ));
    }

    private void register(String email, String password) throws Exception {
        HttpResponse<String> res = post("/auth/register", null, Map.of(
                "email", email,
                "password", password
        ), null);
        assertThat(res.statusCode()).isBetween(200, 299);
    }

    private String login(String email, String password, String xForwardedFor) throws Exception {
        String ip = xForwardedFor != null ? xForwardedFor : ("198.51.100." + Math.floorMod(email.hashCode() + (int) Instant.now().toEpochMilli(), 200));
        HttpResponse<String> res = post("/auth/login", null, Map.of(
                "email", email,
                "password", password
        ), ip);
        assertThat(res.statusCode()).isBetween(200, 299);
        Map<?, ?> body = om.readValue(res.body(), Map.class);
        return String.valueOf(body.get("accessToken"));
    }

    private Long createSecret(String token, String title, String data) throws Exception {
        HttpResponse<String> res = post("/api/secrets", token, Map.of(
                "title", title,
                "data", data
        ), null);
        assertThat(res.statusCode()).isBetween(200, 299);
        Map<?, ?> body = om.readValue(res.body(), Map.class);
        return ((Number) body.get("id")).longValue();
    }

    private HttpResponse<String> get(String path, String token, String xForwardedFor) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .GET();

        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        if (xForwardedFor != null) {
            builder.header("X-Forwarded-For", xForwardedFor);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String token, Object body, String xForwardedFor) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(om.writeValueAsString(body)));

        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        if (xForwardedFor != null) {
            builder.header("X-Forwarded-For", xForwardedFor);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
