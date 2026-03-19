package ru.mfa.antivirus.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.mfa.antivirus.dto.SignaturePublicKeyResponse;
import ru.mfa.antivirus.dto.Ticket;
import ru.mfa.antivirus.dto.TicketResponse;
import ru.mfa.antivirus.model.Device;
import ru.mfa.antivirus.model.License;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.Base64;

@Service
public class TicketSignatureService {
    private final String algorithm;
    private final long ticketTtlSeconds;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public TicketSignatureService(@Value("${ticket.signature.algorithm:SHA256withRSA}") String algorithm,
            @Value("${ticket.ttl-seconds:300}") long ticketTtlSeconds,
            @Value("${ticket.signature.private-key:}") String privateKeyBase64,
            @Value("${ticket.signature.public-key:}") String publicKeyBase64) {
        this.algorithm = algorithm;
        this.ticketTtlSeconds = ticketTtlSeconds;

        KeyPair keyPair = resolveKeyPair(privateKeyBase64, publicKeyBase64);
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // Формирует Ticket и подписывает его ЭЦП для клиента.
    public TicketResponse buildTicketResponse(License license, Device device) {
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime activationDate = license.getFirstActivationDate() != null ? license.getFirstActivationDate() : now;
        OffsetDateTime expirationDate = license.getEndingDate() != null ? license.getEndingDate() : now;
        Long userId = license.getUser() != null ? license.getUser().getId() : null;

        Ticket ticket = new Ticket(
                now,
                ticketTtlSeconds,
                activationDate,
                expirationDate,
                userId,
                device.getId(),
                license.isBlocked());

        return new TicketResponse(ticket, signTicket(ticket));
    }

    // Возвращает публичный ключ сервера для проверки подписи на стороне клиента.
    public SignaturePublicKeyResponse getPublicKeyResponse() {
        String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return new SignaturePublicKeyResponse(algorithm, publicKeyEncoded, ticketTtlSeconds);
    }

    // Вычисляет ЭЦП от канонической строки Ticket.
    private String signTicket(Ticket ticket) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(canonicalTicket(ticket).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Failed to sign ticket", ex);
        }
    }

    // Собирает каноническое представление Ticket для стабильной подписи.
    private String canonicalTicket(Ticket ticket) {
        return String.join("|",
                value(ticket.getServerDate()),
                String.valueOf(ticket.getTicketTtlSeconds()),
                value(ticket.getLicenseActivationDate()),
                value(ticket.getLicenseExpirationDate()),
                value(ticket.getUserId()),
                value(ticket.getDeviceId()),
                String.valueOf(ticket.isLicenseBlocked()));
    }

    // Приводит объект к строке и безопасно обрабатывает null.
    private String value(Object value) {
        return value == null ? "" : value.toString();
    }

    // Загружает ключи из конфигурации или генерирует временную пару, если ключи не заданы.
    private KeyPair resolveKeyPair(String privateKeyBase64, String publicKeyBase64) {
        if (isBlank(privateKeyBase64) || isBlank(publicKeyBase64)) {
            return generateKeyPair();
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] privateBytes = Base64.getDecoder().decode(clearBase64(privateKeyBase64));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

            byte[] publicBytes = Base64.getDecoder().decode(clearBase64(publicKeyBase64));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));

            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid ticket signature key pair", ex);
        }
    }

    // Генерирует новую RSA-пару ключей для подписи тикетов.
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Cannot generate RSA key pair for ticket signing", ex);
        }
    }

    // Очищает base64-строку ключа от пробелов и переносов.
    private String clearBase64(String raw) {
        return raw.replaceAll("\\s+", "");
    }

    // Проверяет, что строка пуста или состоит из пробелов.
    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
