package ru.mfa.antivirus.binary;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class MultipartMixedResponseFactory {

    // Формирует multipart/mixed ответ с двумя бинарными частями.
    public ResponseEntity<byte[]> build(byte[] manifestBytes, byte[] dataBytes) {
        String boundary = "sigbin-" + UUID.randomUUID().toString().replace("-", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        writePart(out, boundary, "manifest.bin", manifestBytes);
        writePart(out, boundary, "data.bin", dataBytes);
        out.writeBytes(("--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII));

        byte[] body = out.toByteArray();
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, "multipart/mixed; boundary=" + boundary);
        headers.setContentLength(body.length);
        headers.set(HttpHeaders.CACHE_CONTROL, "no-store");

        return ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.parseMediaType("multipart/mixed; boundary=" + boundary))
                .body(body);
    }

    // Записывает одну часть multipart с бинарным содержимым.
    private void writePart(ByteArrayOutputStream out, String boundary, String filename, byte[] body) {
        out.writeBytes(("--" + boundary + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(("Content-Disposition: attachment; filename=\"" + filename + "\"\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.writeBytes("Content-Type: application/octet-stream\r\n".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(("Content-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(body);
        out.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
    }
}
