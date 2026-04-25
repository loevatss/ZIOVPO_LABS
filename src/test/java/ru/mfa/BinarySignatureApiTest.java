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
import ru.mfa.antivirus.signature.PayloadSigningService;
import ru.mfa.antivirus.signature.SignatureProperties;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BinarySignatureApiTest {
    private static final String MANIFEST_MAGIC = "MF-TAYA";
    private static final String DATA_MAGIC = "DB-TAYA";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PayloadSigningService payloadSigningService;

    @Autowired
    private SignatureProperties signatureProperties;

    // Возвращает базовый URL тестового сервера.
    private String baseUrl() {
        return "http://localhost:" + port;
    }

    // Генерирует уникальный логин для изоляции тестов.
    private String uniqueUsername(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    // Регистрирует пользователя с выбранной ролью.
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

    // Выполняет логин и возвращает access/refresh токены.
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

    // Формирует заголовки для JSON-запросов с Bearer токеном.
    private HttpHeaders jsonAuthHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        return headers;
    }

    // Выполняет JSON-запрос и возвращает строковое тело.
    private ResponseEntity<String> exchangeJson(String path, HttpMethod method, String accessToken, Object body) {
        HttpEntity<?> entity = body == null
                ? new HttpEntity<>(jsonAuthHeaders(accessToken))
                : new HttpEntity<>(body, jsonAuthHeaders(accessToken));
        return restTemplate.exchange(baseUrl() + path, method, entity, String.class);
    }

    // Выполняет запрос к binary API и возвращает байтовое тело.
    private ResponseEntity<byte[]> exchangeBinary(String path, HttpMethod method, String accessToken, Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        if (body != null) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }
        HttpEntity<?> entity = body == null ? new HttpEntity<>(headers) : new HttpEntity<>(body, headers);
        return restTemplate.exchange(baseUrl() + path, method, entity, byte[].class);
    }

    // Создает сигнатуру через JSON API и возвращает JSON ответа.
    private JsonNode createSignature(String accessToken,
            String threatName,
            String firstBytesHex,
            String remainderHashHex,
            long remainderLength,
            String fileType,
            long offsetStart,
            long offsetEnd) throws Exception {
        Map<String, Object> payload = Map.of(
                "threatName", threatName,
                "firstBytesHex", firstBytesHex,
                "remainderHashHex", remainderHashHex,
                "remainderLength", remainderLength,
                "fileType", fileType,
                "offsetStart", offsetStart,
                "offsetEnd", offsetEnd);

        ResponseEntity<String> response = exchangeJson("/api/signatures", HttpMethod.POST, accessToken, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return objectMapper.readTree(response.getBody());
    }

    // Проверяет бинарный модуль по требованиям Lab_5.
    @Test
    void binaryApiMeetsLab5Requirements() throws Exception {
        String adminUsername = uniqueUsername("bin-admin");
        String userUsername = uniqueUsername("bin-user");
        String password = "Admin@1234";

        register(adminUsername, password, "ADMIN");
        register(userUsername, password, "USER");

        TokenPairResponse adminTokens = login(adminUsername, password);
        TokenPairResponse userTokens = login(userUsername, password);

        JsonNode actualNode = createSignature(
                adminTokens.getAccessToken(),
                "Trojan.Binary.Actual",
                "A1B2C3D4",
                "EEFF0011AA22",
                128,
                "exe",
                0,
                64);

        JsonNode deletedNode = createSignature(
                adminTokens.getAccessToken(),
                "Trojan.Binary.Deleted",
                "CAFEBABE",
                "010203040506",
                512,
                "dll",
                4,
                260);

        UUID actualId = UUID.fromString(actualNode.path("id").asText());
        UUID deletedId = UUID.fromString(deletedNode.path("id").asText());

        Instant sinceBeforeDelete = Instant.now();
        ResponseEntity<String> deleteResponse = exchangeJson(
                "/api/signatures/" + deletedId,
                HttpMethod.DELETE,
                adminTokens.getAccessToken(),
                null);
        assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<byte[]> fullResponse = exchangeBinary(
                "/api/binary/signatures/full",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(fullResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(fullResponse.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).startsWith("multipart/mixed");

        Map<String, byte[]> fullParts = extractMultipartParts(fullResponse);
        ParsedData fullData = parseData(fullParts.get("data.bin"));
        ParsedManifest fullManifest = parseManifest(fullParts.get("manifest.bin"));

        assertThat(fullData.recordCount()).isEqualTo(1);
        assertThat(fullManifest.exportType()).isEqualTo(1);
        assertThat(fullManifest.sinceEpochMillis()).isEqualTo(-1L);
        assertThat(fullManifest.recordCount()).isEqualTo(1);
        assertThat(fullManifest.entries().getFirst().id()).isEqualTo(actualId);
        assertThat(fullManifest.entries().getFirst().statusCode()).isEqualTo(1);
        assertThat(fullData.records().getFirst().threatName()).isEqualTo("Trojan.Binary.Actual");
        assertThat(fullData.records().getFirst().fileType()).isEqualTo("exe");
        assertThat(fullData.records().getFirst().firstBytes()).containsExactly(hexToBytes("A1B2C3D4"));
        assertThat(fullData.records().getFirst().remainderHash()).containsExactly(hexToBytes("EEFF0011AA22"));
        assertThat(fullData.records().getFirst().offsetStart()).isEqualTo(0);
        assertThat(fullData.records().getFirst().offsetEnd()).isEqualTo(64);
        assertThat(fullManifest.dataSha256()).containsExactly(sha256(fullParts.get("data.bin")));
        assertThat(fullManifest.entries().getFirst().recordSignatureBytes())
                .containsExactly(Base64.getDecoder().decode(actualNode.path("digitalSignatureBase64").asText()));
        assertThat(verifyManifestSignature(fullManifest)).isTrue();
        assertOffsets(fullManifest, fullData);

        ResponseEntity<byte[]> incrementResponse = exchangeBinary(
                "/api/binary/signatures/increment?since=" + sinceBeforeDelete.toString(),
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(incrementResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        Map<String, byte[]> incrementParts = extractMultipartParts(incrementResponse);
        ParsedManifest incrementManifest = parseManifest(incrementParts.get("manifest.bin"));
        ParsedData incrementData = parseData(incrementParts.get("data.bin"));

        assertThat(incrementManifest.exportType()).isEqualTo(2);
        assertThat(incrementManifest.sinceEpochMillis()).isEqualTo(sinceBeforeDelete.toEpochMilli());
        assertThat(incrementManifest.recordCount()).isEqualTo(1);
        assertThat(incrementManifest.entries().getFirst().id()).isEqualTo(deletedId);
        assertThat(incrementManifest.entries().getFirst().statusCode()).isEqualTo(2);
        assertThat(incrementData.recordCount()).isEqualTo(1);
        assertThat(verifyManifestSignature(incrementManifest)).isTrue();
        assertOffsets(incrementManifest, incrementData);

        ResponseEntity<byte[]> byIdsResponse = exchangeBinary(
                "/api/binary/signatures/by-ids",
                HttpMethod.POST,
                userTokens.getAccessToken(),
                Map.of("ids", List.of(actualId, deletedId, UUID.randomUUID())));
        assertThat(byIdsResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        Map<String, byte[]> byIdsParts = extractMultipartParts(byIdsResponse);
        ParsedManifest byIdsManifest = parseManifest(byIdsParts.get("manifest.bin"));
        ParsedData byIdsData = parseData(byIdsParts.get("data.bin"));

        assertThat(byIdsManifest.exportType()).isEqualTo(3);
        assertThat(byIdsManifest.sinceEpochMillis()).isEqualTo(-1L);
        assertThat(byIdsManifest.recordCount()).isEqualTo(2);
        assertThat(byIdsData.recordCount()).isEqualTo(2);
        assertThat(byIdsManifest.entries().get(0).id()).isEqualTo(actualId);
        assertThat(byIdsManifest.entries().get(1).id()).isEqualTo(deletedId);
        assertThat(verifyManifestSignature(byIdsManifest)).isTrue();
        assertOffsets(byIdsManifest, byIdsData);

        ResponseEntity<String> incrementWithoutSince = exchangeJson(
                "/api/binary/signatures/increment",
                HttpMethod.GET,
                userTokens.getAccessToken(),
                null);
        assertThat(incrementWithoutSince.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<String> byIdsEmpty = exchangeJson(
                "/api/binary/signatures/by-ids",
                HttpMethod.POST,
                userTokens.getAccessToken(),
                Map.of("ids", List.of()));
        assertThat(byIdsEmpty.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // Разбирает multipart/mixed тело на части manifest.bin и data.bin.
    private Map<String, byte[]> extractMultipartParts(ResponseEntity<byte[]> response) {
        byte[] body = Objects.requireNonNull(response.getBody(), "response body is null");
        String contentType = response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        assertThat(contentType).isNotBlank();

        String boundary = extractBoundary(contentType);
        String boundaryMarker = "--" + boundary;
        String raw = new String(body, StandardCharsets.ISO_8859_1);

        Map<String, byte[]> parts = new LinkedHashMap<>();
        String[] chunks = raw.split(Pattern.quote(boundaryMarker));
        for (String chunk : chunks) {
            if (chunk == null || chunk.isBlank()) {
                continue;
            }
            if (chunk.startsWith("--")) {
                break;
            }

            String normalized = chunk.startsWith("\r\n") ? chunk.substring(2) : chunk;
            int headerEnd = normalized.indexOf("\r\n\r\n");
            if (headerEnd < 0) {
                continue;
            }

            String headersText = normalized.substring(0, headerEnd);
            String contentText = normalized.substring(headerEnd + 4);

            String filename = extractFilename(headersText);
            int contentLength = extractContentLength(headersText);

            if (contentText.length() < contentLength) {
                throw new IllegalStateException("Multipart part is shorter than declared Content-Length");
            }

            byte[] partBytes = contentText.substring(0, contentLength).getBytes(StandardCharsets.ISO_8859_1);
            parts.put(filename, partBytes);
        }

        assertThat(parts).containsKeys("manifest.bin", "data.bin");
        return parts;
    }

    // Извлекает boundary из Content-Type.
    private String extractBoundary(String contentType) {
        for (String token : contentType.split(";")) {
            String trimmed = token.trim();
            if (trimmed.startsWith("boundary=")) {
                String boundaryValue = trimmed.substring("boundary=".length());
                if (boundaryValue.startsWith("\"") && boundaryValue.endsWith("\"") && boundaryValue.length() >= 2) {
                    return boundaryValue.substring(1, boundaryValue.length() - 1);
                }
                return boundaryValue;
            }
        }
        throw new IllegalStateException("Boundary not found in Content-Type: " + contentType);
    }

    // Извлекает filename из заголовка Content-Disposition.
    private String extractFilename(String headersText) {
        Matcher matcher = Pattern.compile("filename=\"([^\"]+)\"").matcher(headersText);
        if (!matcher.find()) {
            throw new IllegalStateException("filename not found in multipart headers: " + headersText);
        }
        return matcher.group(1);
    }

    // Извлекает Content-Length из заголовков части.
    private int extractContentLength(String headersText) {
        Matcher matcher = Pattern.compile("Content-Length:\\s*(\\d+)").matcher(headersText);
        if (!matcher.find()) {
            throw new IllegalStateException("Content-Length not found in multipart headers: " + headersText);
        }
        return Integer.parseInt(matcher.group(1));
    }

    // Парсит бинарный data.bin.
    private ParsedData parseData(byte[] bytes) {
        BinaryReader reader = new BinaryReader(bytes);
        String magic = reader.readAscii(DATA_MAGIC.length());
        assertThat(magic).isEqualTo(DATA_MAGIC);

        int version = reader.readUInt16();
        long recordCount = reader.readUInt32();

        assertThat(version).isEqualTo(1);

        List<DataRecord> records = new ArrayList<>();
        for (int i = 0; i < recordCount; i++) {
            int startPos = reader.position();
            String threatName = reader.readStringUtf8();
            byte[] firstBytes = reader.readByteArray();
            byte[] remainderHash = reader.readByteArray();
            long remainderLength = reader.readInt64();
            String fileType = reader.readStringUtf8();
            long offsetStart = reader.readInt64();
            long offsetEnd = reader.readInt64();
            int recordLength = reader.position() - startPos;
            records.add(new DataRecord(threatName, firstBytes, remainderHash, remainderLength, fileType, offsetStart, offsetEnd,
                    recordLength));
        }

        assertThat(reader.remaining()).isEqualTo(0);
        return new ParsedData(version, (int) recordCount, records, bytes);
    }

    // Парсит бинарный manifest.bin.
    private ParsedManifest parseManifest(byte[] bytes) {
        BinaryReader reader = new BinaryReader(bytes);
        String magic = reader.readAscii(MANIFEST_MAGIC.length());
        assertThat(magic).isEqualTo(MANIFEST_MAGIC);

        int version = reader.readUInt16();
        int exportType = reader.readUInt8();
        long generatedAtEpochMillis = reader.readInt64();
        long sinceEpochMillis = reader.readInt64();
        long recordCount = reader.readUInt32();
        byte[] dataSha256 = reader.readBytes(32);

        assertThat(version).isEqualTo(1);
        assertThat(generatedAtEpochMillis).isPositive();

        List<ManifestEntry> entries = new ArrayList<>();
        for (int i = 0; i < recordCount; i++) {
            UUID id = reader.readUuid();
            int statusCode = reader.readUInt8();
            long updatedAtEpochMillis = reader.readInt64();
            long dataOffset = reader.readUInt32();
            long dataLength = reader.readUInt32();
            int recordSignatureLength = (int) reader.readUInt32();
            byte[] recordSignatureBytes = reader.readBytes(recordSignatureLength);
            entries.add(new ManifestEntry(id, statusCode, updatedAtEpochMillis, dataOffset, dataLength, recordSignatureBytes));
        }

        int unsignedLength = reader.position();
        int manifestSignatureLength = (int) reader.readUInt32();
        byte[] manifestSignatureBytes = reader.readBytes(manifestSignatureLength);
        assertThat(reader.remaining()).isEqualTo(0);

        byte[] unsignedBytes = Arrays.copyOf(bytes, unsignedLength);
        return new ParsedManifest(
                version,
                exportType,
                generatedAtEpochMillis,
                sinceEpochMillis,
                (int) recordCount,
                dataSha256,
                entries,
                unsignedBytes,
                manifestSignatureBytes);
    }

    // Проверяет подпись неподписанной части manifest.bin.
    private boolean verifyManifestSignature(ParsedManifest manifest) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(payloadSigningService.getPublicKeyBase64());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        Signature verifier = Signature.getInstance(signatureProperties.getAlgorithm());
        verifier.initVerify(publicKey);
        verifier.update(manifest.unsignedBytes());
        return verifier.verify(manifest.manifestSignatureBytes());
    }

    // Сверяет смещения/длины записей в манифесте с реальными data-записями.
    private void assertOffsets(ParsedManifest manifest, ParsedData data) {
        long runningOffset = 0L;
        for (int i = 0; i < manifest.entries().size(); i++) {
            ManifestEntry entry = manifest.entries().get(i);
            DataRecord record = data.records().get(i);
            assertThat(entry.dataOffset()).isEqualTo(runningOffset);
            assertThat(entry.dataLength()).isEqualTo(record.recordLength());
            runningOffset += record.recordLength();
        }
    }

    // Вычисляет SHA-256 для массива байт.
    private byte[] sha256(byte[] bytes) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    // Декодирует HEX-строку в byte[].
    private byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    private record ParsedData(int version, int recordCount, List<DataRecord> records, byte[] rawBytes) {
    }

    private record DataRecord(String threatName,
            byte[] firstBytes,
            byte[] remainderHash,
            long remainderLength,
            String fileType,
            long offsetStart,
            long offsetEnd,
            int recordLength) {
    }

    private record ParsedManifest(int version,
            int exportType,
            long generatedAtEpochMillis,
            long sinceEpochMillis,
            int recordCount,
            byte[] dataSha256,
            List<ManifestEntry> entries,
            byte[] unsignedBytes,
            byte[] manifestSignatureBytes) {
    }

    private record ManifestEntry(UUID id,
            int statusCode,
            long updatedAtEpochMillis,
            long dataOffset,
            long dataLength,
            byte[] recordSignatureBytes) {
    }

    private static final class BinaryReader {
        private final byte[] bytes;
        private int position;

        private BinaryReader(byte[] bytes) {
            this.bytes = bytes == null ? new byte[0] : bytes;
            this.position = 0;
        }

        // Возвращает текущую позицию чтения.
        private int position() {
            return position;
        }

        // Возвращает количество непрочитанных байт.
        private int remaining() {
            return bytes.length - position;
        }

        // Читает uint8.
        private int readUInt8() {
            ensureAvailable(1);
            return bytes[position++] & 0xFF;
        }

        // Читает uint16 BigEndian.
        private int readUInt16() {
            ensureAvailable(2);
            int value = ((bytes[position] & 0xFF) << 8)
                    | (bytes[position + 1] & 0xFF);
            position += 2;
            return value;
        }

        // Читает uint32 BigEndian.
        private long readUInt32() {
            ensureAvailable(4);
            long value = ((long) (bytes[position] & 0xFF) << 24)
                    | ((long) (bytes[position + 1] & 0xFF) << 16)
                    | ((long) (bytes[position + 2] & 0xFF) << 8)
                    | ((long) (bytes[position + 3] & 0xFF));
            position += 4;
            return value;
        }

        // Читает int64 BigEndian.
        private long readInt64() {
            ensureAvailable(8);
            long value = ((long) (bytes[position] & 0xFF) << 56)
                    | ((long) (bytes[position + 1] & 0xFF) << 48)
                    | ((long) (bytes[position + 2] & 0xFF) << 40)
                    | ((long) (bytes[position + 3] & 0xFF) << 32)
                    | ((long) (bytes[position + 4] & 0xFF) << 24)
                    | ((long) (bytes[position + 5] & 0xFF) << 16)
                    | ((long) (bytes[position + 6] & 0xFF) << 8)
                    | ((long) (bytes[position + 7] & 0xFF));
            position += 8;
            return value;
        }

        // Читает UUID как две int64 части.
        private UUID readUuid() {
            long most = readInt64();
            long least = readInt64();
            return new UUID(most, least);
        }

        // Читает ASCII-строку фиксированной длины.
        private String readAscii(int length) {
            return new String(readBytes(length), StandardCharsets.US_ASCII);
        }

        // Читает UTF-8 строку uint16 length + bytes.
        private String readStringUtf8() {
            int length = readUInt16();
            return new String(readBytes(length), StandardCharsets.UTF_8);
        }

        // Читает byte[] как uint32 length + bytes.
        private byte[] readByteArray() {
            int length = (int) readUInt32();
            return readBytes(length);
        }

        // Читает байты фиксированной длины.
        private byte[] readBytes(int length) {
            ensureAvailable(length);
            byte[] value = Arrays.copyOfRange(bytes, position, position + length);
            position += length;
            return value;
        }

        private void ensureAvailable(int length) {
            if (length < 0 || position + length > bytes.length) {
                throw new IllegalStateException("Binary payload is truncated");
            }
        }
    }
}
