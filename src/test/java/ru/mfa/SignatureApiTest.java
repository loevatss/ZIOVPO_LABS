package ru.mfa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import ru.mfa.antivirus.dto.TokenPairResponse;
import ru.mfa.antivirus.dto.UserResponse;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SignatureApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    // Возвращает базовый URL тестового сервера.
    private String baseUrl() {
        return "http://localhost:" + port;
    }

    // Генерирует уникальный логин пользователя для изоляции тестов.
    private String uniqueUsername(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    // Регистрирует пользователя с указанной ролью.
    private void register(String username, String password, String role) {
        Map<String, Object> payload = Map.of(
                "username", username,
                "password", password,
                "role", role);

        ResponseEntity<UserResponse> response = restTemplate.postForEntity(
                baseUrl() + "/api/auth/register",
                payload,
                UserResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    // Выполняет логин и возвращает пару JWT токенов.
    private TokenPairResponse login(String username, String password) {
        Map<String, Object> payload = Map.of(
                "username", username,
                "password", password);

        ResponseEntity<TokenPairResponse> response = restTemplate.postForEntity(
                baseUrl() + "/api/auth/login",
                payload,
                TokenPairResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        return response.getBody();
    }

    // Формирует HTTP-заголовки с JWT авторизацией.
    private HttpHeaders authHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        return headers;
    }

    // Выполняет универсальный HTTP-запрос в тесте.
    private ResponseEntity<String> exchange(String path, HttpMethod method, String accessToken, Object body) {
        HttpEntity<?> entity = body == null
                ? new HttpEntity<>(authHeaders(accessToken))
                : new HttpEntity<>(body, authHeaders(accessToken));

        return restTemplate.exchange(baseUrl() + path, method, entity, String.class);
    }

    // Собирает валидный payload для create/update сигнатуры.
    private Map<String, Object> signaturePayload(String threatName, String firstBytesHex, String remainderHashHex,
            long remainderLength, String fileType, long offsetStart, long offsetEnd) {
        return Map.of(
                "threatName", threatName,
                "firstBytesHex", firstBytesHex,
                "remainderHashHex", remainderHashHex,
                "remainderLength", remainderLength,
                "fileType", fileType,
                "offsetStart", offsetStart,
                "offsetEnd", offsetEnd);
    }

    // Ищет сигнатуру по id в JSON-массиве.
    private JsonNode findById(JsonNode array, String signatureId) {
        for (JsonNode node : array) {
            if (signatureId.equals(node.path("id").asText())) {
                return node;
            }
        }
        return null;
    }

    // Проверяет модуль сигнатур по требованиям Lab_4.
    @Test
    void signatureModuleMeetsLab4Requirements() throws Exception {
        String adminUsername = uniqueUsername("sig-admin");
        String userUsername = uniqueUsername("sig-user");
        String password = "Admin@1234";

        register(adminUsername, password, "ADMIN");
        register(userUsername, password, "USER");

        TokenPairResponse adminTokens = login(adminUsername, password);
        TokenPairResponse userTokens = login(userUsername, password);

        Map<String, Object> createPayload = signaturePayload(
                "Trojan.Test.A",
                "A1B2C3D4",
                "EEFF0011AA22",
                128,
                "exe",
                0,
                64);

        ResponseEntity<String> createByUser = exchange(
                "/api/signatures",
                HttpMethod.POST,
                userTokens.getAccessToken(),
                createPayload);
        assertThat(createByUser.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        ResponseEntity<String> createResponse = exchange(
                "/api/signatures",
                HttpMethod.POST,
                adminTokens.getAccessToken(),
                createPayload);
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        JsonNode created = objectMapper.readTree(createResponse.getBody());
        String signatureId = created.path("id").asText();
        String signatureAfterCreate = created.path("digitalSignatureBase64").asText();
        assertThat(signatureId).isNotBlank();
        assertThat(signatureAfterCreate).isNotBlank();
        assertThat(created.path("status").asText()).isEqualTo("ACTUAL");

        ResponseEntity<String> fullAsUser = exchange(
                "/api/signatures",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(fullAsUser.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode fullList = objectMapper.readTree(fullAsUser.getBody());
        assertThat(findById(fullList, signatureId)).isNotNull();

        ResponseEntity<String> byIdResponse = exchange(
                "/api/signatures/" + signatureId,
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(byIdResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> byIdsResponse = exchange(
                "/api/signatures/by-ids",
                HttpMethod.POST,
                userTokens.getAccessToken(),
                Map.of("ids", new String[] { signatureId, UUID.randomUUID().toString() }));
        assertThat(byIdsResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode byIdsList = objectMapper.readTree(byIdsResponse.getBody());
        assertThat(byIdsList.isArray()).isTrue();
        assertThat(byIdsList.size()).isEqualTo(1);

        Map<String, Object> updatePayload = signaturePayload(
                "Trojan.Test.A.Updated",
                "A1B2C3D4",
                "EEFF0011AA22",
                256,
                "dll",
                4,
                96);

        ResponseEntity<String> updateResponse = exchange(
                "/api/signatures/" + signatureId,
                HttpMethod.PUT,
                adminTokens.getAccessToken(),
                updatePayload);
        assertThat(updateResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        JsonNode updated = objectMapper.readTree(updateResponse.getBody());
        String signatureAfterUpdate = updated.path("digitalSignatureBase64").asText();
        assertThat(signatureAfterUpdate).isNotBlank();
        assertThat(signatureAfterUpdate).isNotEqualTo(signatureAfterCreate);

        ResponseEntity<String> historyAfterUpdate = exchange(
                "/api/signatures/" + signatureId + "/history",
                HttpMethod.GET,
                adminTokens.getAccessToken(),
                null);
        assertThat(historyAfterUpdate.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode history1 = objectMapper.readTree(historyAfterUpdate.getBody());
        assertThat(history1.size()).isGreaterThanOrEqualTo(1);

        ResponseEntity<String> auditAfterUpdate = exchange(
                "/api/signatures/" + signatureId + "/audit",
                HttpMethod.GET,
                adminTokens.getAccessToken(),
                null);
        assertThat(auditAfterUpdate.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode audit1 = objectMapper.readTree(auditAfterUpdate.getBody());
        assertThat(audit1.size()).isGreaterThanOrEqualTo(2);

        ResponseEntity<String> historyByUserDenied = exchange(
                "/api/signatures/" + signatureId + "/history",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(historyByUserDenied.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        Instant sinceBeforeDelete = Instant.now().minusSeconds(1);

        ResponseEntity<String> deleteResponse = exchange(
                "/api/signatures/" + signatureId,
                HttpMethod.DELETE,
                adminTokens.getAccessToken(),
                null);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<String> fullAfterDelete = exchange(
                "/api/signatures",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(fullAfterDelete.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode fullAfterDeleteList = objectMapper.readTree(fullAfterDelete.getBody());
        assertThat(findById(fullAfterDeleteList, signatureId)).isNull();

        ResponseEntity<String> incrementResponse = exchange(
                "/api/signatures/increment?since=" + sinceBeforeDelete,
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(incrementResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode incrementList = objectMapper.readTree(incrementResponse.getBody());
        JsonNode deletedNode = findById(incrementList, signatureId);
        assertThat(deletedNode).isNotNull();
        assertThat(deletedNode.path("status").asText()).isEqualTo("DELETED");

        ResponseEntity<String> historyAfterDelete = exchange(
                "/api/signatures/" + signatureId + "/history",
                HttpMethod.GET,
                adminTokens.getAccessToken(),
                null);
        assertThat(historyAfterDelete.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode history2 = objectMapper.readTree(historyAfterDelete.getBody());
        assertThat(history2.size()).isGreaterThanOrEqualTo(2);

        ResponseEntity<String> auditAfterDelete = exchange(
                "/api/signatures/" + signatureId + "/audit",
                HttpMethod.GET,
                adminTokens.getAccessToken(),
                null);
        assertThat(auditAfterDelete.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode audit2 = objectMapper.readTree(auditAfterDelete.getBody());
        assertThat(audit2.size()).isGreaterThanOrEqualTo(3);

        boolean hasCreate = false;
        boolean hasUpdate = false;
        boolean hasDelete = false;
        for (JsonNode node : audit2) {
            String description = node.path("description").asText("");
            if ("Signature created".equals(description)) {
                hasCreate = true;
            }
            if ("Signature updated".equals(description)) {
                hasUpdate = true;
            }
            if ("Signature logically deleted".equals(description)) {
                hasDelete = true;
            }
        }

        assertThat(hasCreate).isTrue();
        assertThat(hasUpdate).isTrue();
        assertThat(hasDelete).isTrue();

        ResponseEntity<String> incrementWithoutSince = exchange(
                "/api/signatures/increment",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(incrementWithoutSince.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
