package ru.mfa.antivirus.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.mfa.antivirus.dto.SignaturePublicKeyResponse;
import ru.mfa.antivirus.dto.Ticket;
import ru.mfa.antivirus.dto.TicketResponse;
import ru.mfa.antivirus.model.Device;
import ru.mfa.antivirus.model.License;
import ru.mfa.antivirus.signature.PayloadSigningService;
import ru.mfa.antivirus.signature.SignatureProperties;

import java.time.OffsetDateTime;

@Service
public class TicketSignatureService {
    private final long ticketTtlSeconds;
    private final PayloadSigningService payloadSigningService;
    private final SignatureProperties signatureProperties;

    public TicketSignatureService(@Value("${ticket.ttl-seconds:300}") long ticketTtlSeconds,
            PayloadSigningService payloadSigningService,
            SignatureProperties signatureProperties) {
        this.ticketTtlSeconds = ticketTtlSeconds;
        this.payloadSigningService = payloadSigningService;
        this.signatureProperties = signatureProperties;
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

        return new TicketResponse(ticket, payloadSigningService.sign(ticket));
    }

    // Возвращает публичную часть ЭЦП-модуля для клиентской верификации.
    public SignaturePublicKeyResponse getPublicKeyResponse() {
        return new SignaturePublicKeyResponse(
                signatureProperties.getAlgorithm(),
                payloadSigningService.getPublicKeyBase64(),
                payloadSigningService.getCertificatePem(),
                ticketTtlSeconds);
    }
}
