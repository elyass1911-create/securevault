package com.yassin.securevault;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecretAuthorizationITTest extends BaseIntegrationTest {

    @LocalServerPort
    int port;

    private final ObjectMapper om = new ObjectMapper();
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void userB_cannot_reveal_userA_secret_cross_user_access_is_blocked() throws Exception {
        long nonce = Instant.now().toEpochMilli();
        String userAEmail = "usera+" + nonce + "@test.com";
        String userBEmail = "userb+" + nonce + "@test.com";
        String password = "Password123!";
        String title = "A-title-" + nonce;
        String plaintext = "A-secret-" + nonce;

        register(userAEmail, password);
        register(userBEmail, password);

        String tokenA = loginAndGetAccessToken(userAEmail, password);
        String tokenB = loginAndGetAccessToken(userBEmail, password);

        Long secretId = createSecretAndGetId(tokenA, title, plaintext);
        assertThat(secretId).isNotNull();

        HttpResponse<String> revealByA = get("/api/secrets/" + secretId + "/reveal", tokenA);
        assertThat(revealByA.statusCode()).isEqualTo(200);
        Map<?, ?> revealByABody = om.readValue(revealByA.body(), Map.class);
        assertThat(revealByABody.get("data")).isEqualTo(plaintext);

        HttpResponse<String> revealByB = get("/api/secrets/" + secretId + "/reveal", tokenB);
        assertThat(revealByB.statusCode()).isIn(403, 404);
        assertThat(revealByB.statusCode()).isNotEqualTo(200);
        assertThat(revealByB.body()).doesNotContain(plaintext);
    }

    private void register(String email, String password) throws Exception {
        HttpResponse<String> response = post("/auth/register", null, Map.of(
                "email", email,
                "password", password
        ));
        assertThat(response.statusCode()).isBetween(200, 299);
    }

    private String loginAndGetAccessToken(String email, String password) throws Exception {
        HttpResponse<String> response = post("/auth/login", null, Map.of(
                "email", email,
                "password", password
        ));
        assertThat(response.statusCode()).isBetween(200, 299);

        Map<?, ?> body = om.readValue(response.body(), Map.class);
        Object accessToken = body.get("accessToken");
        assertThat(accessToken).isNotNull();
        return accessToken.toString();
    }

    private Long createSecretAndGetId(String token, String title, String data) throws Exception {
        HttpResponse<String> response = post("/api/secrets", token, Map.of(
                "title", title,
                "data", data
        ));
        assertThat(response.statusCode()).isBetween(200, 299);

        Map<?, ?> body = om.readValue(response.body(), Map.class);
        Object id = body.get("id");
        if (id != null) {
            return ((Number) id).longValue();
        }

        HttpResponse<String> listResponse = get("/api/secrets", token);
        assertThat(listResponse.statusCode()).isEqualTo(200);
        List<?> list = om.readValue(listResponse.body(), List.class);
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) {
                continue;
            }
            if (title.equals(map.get("title")) && map.get("id") instanceof Number number) {
                return number.longValue();
            }
        }
        return null;
    }

    private HttpResponse<String> post(String path, String token, Object body) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json");
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(om.writeValueAsString(body))).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpRequest request = builder.GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
