package ru.mfa.antivirus.service;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mfa.antivirus.binary.BinaryExportType;
import ru.mfa.antivirus.binary.BinaryTypeWriter;
import ru.mfa.antivirus.binary.MultipartMixedResponseFactory;
import ru.mfa.antivirus.model.MalwareSignature;
import ru.mfa.antivirus.model.SignatureStatus;
import ru.mfa.antivirus.repository.MalwareSignatureRepository;
import ru.mfa.antivirus.signature.PayloadSigningService;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class BinarySignatureService {
    private static final String MANIFEST_MAGIC = "MF-TAYA";
    private static final String DATA_MAGIC = "DB-TAYA";
    private static final int MANIFEST_VERSION = 1;
    private static final int DATA_VERSION = 1;
    private static final long SINCE_NOT_SET = -1L;

    private final MalwareSignatureRepository signatureRepository;
    private final PayloadSigningService payloadSigningService;
    private final BinaryTypeWriter binaryTypeWriter;
    private final MultipartMixedResponseFactory multipartMixedResponseFactory;

    public BinarySignatureService(MalwareSignatureRepository signatureRepository,
            PayloadSigningService payloadSigningService,
            BinaryTypeWriter binaryTypeWriter,
            MultipartMixedResponseFactory multipartMixedResponseFactory) {
        this.signatureRepository = signatureRepository;
        this.payloadSigningService = payloadSigningService;
        this.binaryTypeWriter = binaryTypeWriter;
        this.multipartMixedResponseFactory = multipartMixedResponseFactory;
    }

    // Формирует бинарный full dump только из ACTUAL сигнатур.
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportFull() {
        List<MalwareSignature> signatures = signatureRepository.findByStatusOrderByUpdatedAtDesc(SignatureStatus.ACTUAL);
        return buildResponse(signatures, BinaryExportType.FULL, SINCE_NOT_SET);
    }

    // Формирует бинарный инкремент после since (включая DELETED).
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportIncrement(Instant since) {
        List<MalwareSignature> signatures = signatureRepository.findByUpdatedAtAfterOrderByUpdatedAtAsc(since);
        return buildResponse(signatures, BinaryExportType.INCREMENT, since.toEpochMilli());
    }

    // Формирует бинарный пакет по списку UUID в исходном порядке.
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> exportByIds(List<UUID> ids) {
        List<UUID> uniqueIds = ids == null ? List.of() : ids.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (uniqueIds.isEmpty()) {
            return buildResponse(List.of(), BinaryExportType.BY_IDS, SINCE_NOT_SET);
        }

        Map<UUID, MalwareSignature> foundById = signatureRepository.findByIdIn(uniqueIds).stream()
                .collect(Collectors.toMap(MalwareSignature::getId, value -> value));

        List<MalwareSignature> ordered = uniqueIds.stream()
                .map(foundById::get)
                .filter(Objects::nonNull)
                .toList();

        return buildResponse(ordered, BinaryExportType.BY_IDS, SINCE_NOT_SET);
    }

    // Собирает manifest.bin, data.bin и multipart/mixed ответ.
    private ResponseEntity<byte[]> buildResponse(List<MalwareSignature> signatures,
            BinaryExportType exportType,
            long sinceEpochMillis) {
        DataPayload dataPayload = buildDataBin(signatures);
        byte[] dataSha256 = sha256(dataPayload.dataBytes());
        byte[] unsignedManifest = buildUnsignedManifest(dataPayload.entries(), exportType, sinceEpochMillis, dataSha256);
        byte[] manifestSignature = payloadSigningService.signBytes(unsignedManifest);
        byte[] signedManifest = appendManifestSignature(unsignedManifest, manifestSignature);
        return multipartMixedResponseFactory.build(signedManifest, dataPayload.dataBytes());
    }

    // Сериализует data.bin и возвращает карту смещений для манифеста.
    private DataPayload buildDataBin(List<MalwareSignature> signatures) {
        ByteArrayOutputStream payloadOut = new ByteArrayOutputStream();
        List<ManifestEntryMeta> entryMeta = new ArrayList<>(signatures.size());

        for (MalwareSignature signature : signatures) {
            byte[] recordBytes = buildDataRecord(signature);
            long offset = payloadOut.size();
            payloadOut.writeBytes(recordBytes);

            byte[] recordSignatureBytes = decodeBase64(signature.getDigitalSignatureBase64(), "digitalSignatureBase64");
            entryMeta.add(new ManifestEntryMeta(signature, offset, recordBytes.length, recordSignatureBytes));
        }

        ByteArrayOutputStream fileOut = new ByteArrayOutputStream();
        binaryTypeWriter.writeMagic(fileOut, DATA_MAGIC);
        binaryTypeWriter.writeUInt16(fileOut, DATA_VERSION);
        binaryTypeWriter.writeUInt32(fileOut, signatures.size());
        fileOut.writeBytes(payloadOut.toByteArray());

        return new DataPayload(fileOut.toByteArray(), entryMeta);
    }

    // Сериализует одну транспортную запись data.bin.
    private byte[] buildDataRecord(MalwareSignature signature) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        binaryTypeWriter.writeStringUtf8(out, signature.getThreatName());
        binaryTypeWriter.writeByteArray(out, decodeHex(signature.getFirstBytesHex(), "firstBytesHex"));
        binaryTypeWriter.writeByteArray(out, decodeHex(signature.getRemainderHashHex(), "remainderHashHex"));
        binaryTypeWriter.writeInt64(out, signature.getRemainderLength());
        binaryTypeWriter.writeStringUtf8(out, signature.getFileType());
        binaryTypeWriter.writeInt64(out, signature.getOffsetStart());
        binaryTypeWriter.writeInt64(out, signature.getOffsetEnd());
        return out.toByteArray();
    }

    // Сериализует неподписанную часть манифеста.
    private byte[] buildUnsignedManifest(List<ManifestEntryMeta> entries,
            BinaryExportType exportType,
            long sinceEpochMillis,
            byte[] dataSha256) {
        if (dataSha256.length != 32) {
            throw new IllegalArgumentException("dataSha256 must be 32 bytes");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        binaryTypeWriter.writeMagic(out, MANIFEST_MAGIC);
        binaryTypeWriter.writeUInt16(out, MANIFEST_VERSION);
        binaryTypeWriter.writeUInt8(out, exportType.getCode());
        binaryTypeWriter.writeInt64(out, Instant.now().toEpochMilli());
        binaryTypeWriter.writeInt64(out, sinceEpochMillis);
        binaryTypeWriter.writeUInt32(out, entries.size());
        out.writeBytes(dataSha256);

        for (ManifestEntryMeta entry : entries) {
            MalwareSignature signature = entry.signature();
            binaryTypeWriter.writeUuid(out, signature.getId());
            binaryTypeWriter.writeUInt8(out, mapStatusCode(signature.getStatus()));
            binaryTypeWriter.writeInt64(out, signature.getUpdatedAt().toEpochMilli());
            binaryTypeWriter.writeUInt32(out, entry.dataOffset());
            binaryTypeWriter.writeUInt32(out, entry.dataLength());
            binaryTypeWriter.writeUInt32(out, entry.recordSignatureBytes().length);
            out.writeBytes(entry.recordSignatureBytes());
        }

        return out.toByteArray();
    }

    // Добавляет в конец манифеста подпись (uint32 length + bytes).
    private byte[] appendManifestSignature(byte[] unsignedManifest, byte[] manifestSignature) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(unsignedManifest);
        binaryTypeWriter.writeUInt32(out, manifestSignature.length);
        out.writeBytes(manifestSignature);
        return out.toByteArray();
    }

    // Вычисляет SHA-256 для любого массива байт.
    private byte[] sha256(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to compute SHA-256", ex);
        }
    }

    // Приводит HEX-строку к сырому byte[].
    private byte[] decodeHex(String hexValue, String fieldName) {
        String normalized = hexValue == null ? "" : hexValue.trim();
        if (normalized.length() % 2 != 0) {
            throw new IllegalStateException(fieldName + " must have even length");
        }

        byte[] out = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            int hi = Character.digit(normalized.charAt(i), 16);
            int lo = Character.digit(normalized.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalStateException(fieldName + " must contain HEX characters only");
            }
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    // Декодирует Base64 поле подписи записи.
    private byte[] decodeBase64(String base64Value, String fieldName) {
        try {
            return Base64.getDecoder().decode(base64Value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Failed to decode " + fieldName, ex);
        }
    }

    // Маппит статус сигнатуры в бинарный statusCode.
    private int mapStatusCode(SignatureStatus status) {
        return switch (status) {
            case ACTUAL -> 1;
            case DELETED -> 2;
        };
    }

    private record ManifestEntryMeta(MalwareSignature signature,
            long dataOffset,
            long dataLength,
            byte[] recordSignatureBytes) {
    }

    private record DataPayload(byte[] dataBytes, List<ManifestEntryMeta> entries) {
    }
}
