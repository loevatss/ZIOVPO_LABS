package ru.mfa.antivirus.signature;

import org.springframework.stereotype.Service;

import java.security.Signature;
import java.util.Base64;

@Service
public class PayloadSigningService {
    private final SignatureProperties signatureProperties;
    private final SignatureKeyStoreService keyStoreService;
    private final JsonCanonicalizer jsonCanonicalizer;

    public PayloadSigningService(SignatureProperties signatureProperties,
            SignatureKeyStoreService keyStoreService,
            JsonCanonicalizer jsonCanonicalizer) {
        this.signatureProperties = signatureProperties;
        this.keyStoreService = keyStoreService;
        this.jsonCanonicalizer = jsonCanonicalizer;
    }

    // Подписывает произвольный payload: canonical JSON -> UTF-8 -> SHA256withRSA -> Base64.
    public String sign(Object payload) {
        try {
            SignatureKeyMaterial keyMaterial = keyStoreService.getOrLoad();
            byte[] canonicalBytes = jsonCanonicalizer.canonicalizeToUtf8(payload);

            Signature signature = Signature.getInstance(signatureProperties.getAlgorithm());
            signature.initSign(keyMaterial.getPrivateKey());
            signature.update(canonicalBytes);

            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to sign payload", ex);
        }
    }

    // Возвращает публичный ключ в Base64 для клиентской проверки подписи.
    public String getPublicKeyBase64() {
        SignatureKeyMaterial keyMaterial = keyStoreService.getOrLoad();
        return Base64.getEncoder().encodeToString(keyMaterial.getPublicKey().getEncoded());
    }

    // Возвращает сертификат подписи в PEM-формате.
    public String getCertificatePem() {
        try {
            SignatureKeyMaterial keyMaterial = keyStoreService.getOrLoad();
            String certificateBase64 = Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(keyMaterial.getCertificate().getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + certificateBase64 + "\n-----END CERTIFICATE-----";
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to export certificate", ex);
        }
    }
}
