package com.yassin.securevault;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFlowITTest extends BaseIntegrationTest {

    @LocalServerPort
    int port;

    private final ObjectMapper om = new ObjectMapper();

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void register_then_login_returns_token() throws Exception {
        String email = "user1@test.com";
        String password = "Password123!";

        // register
        HttpResponse<String> registerRes = post(
                "/auth/register",
                Map.of("email", email, "password", password)
        );
        assertThat(registerRes.statusCode()).isBetween(200, 299);

        // login
        HttpResponse<String> loginRes = post(
                "/auth/login",
                Map.of("email", email, "password", password)
        );
        assertThat(loginRes.statusCode()).isBetween(200, 299);

        Map<?, ?> body = om.readValue(loginRes.body(), Map.class);
        assertThat(body.get("accessToken")).isNotNull();
    }

    private HttpResponse<String> post(String path, Object body) throws Exception {
        String json = om.writeValueAsString(body);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
