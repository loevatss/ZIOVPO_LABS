package ru.mfa.antivirus.signature;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@Service
public class SignatureKeyStoreService {
    private final SignatureProperties properties;
    private final Object lock = new Object();
    private volatile SignatureKeyMaterial cached;

    public SignatureKeyStoreService(SignatureProperties properties) {
        this.properties = properties;
    }

    // Возвращает ключевой материал для подписи, загружая его из keystore один раз и кэшируя в памяти.
    public SignatureKeyMaterial getOrLoad() {
        if (cached != null) {
            return cached;
        }

        synchronized (lock) {
            if (cached == null) {
                cached = loadFromKeyStore();
            }
            return cached;
        }
    }

    // Загружает приватный ключ и сертификат из keystore по настройкам приложения.
    private SignatureKeyMaterial loadFromKeyStore() {
        validateRequiredProperties();

        char[] storePassword = properties.getKeyStorePassword().toCharArray();
        char[] keyPassword = resolveKeyPassword();

        try {
            KeyStore keyStore = KeyStore.getInstance(properties.getKeyStoreType());
            try (InputStream inputStream = openKeyStoreStream(properties.getKeyStorePath())) {
                keyStore.load(inputStream, storePassword);
            }

            Key key = keyStore.getKey(properties.getKeyAlias(), keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new IllegalStateException("Key alias does not contain a private key: " + properties.getKeyAlias());
            }

            Certificate certificate = keyStore.getCertificate(properties.getKeyAlias());
            if (!(certificate instanceof X509Certificate x509Certificate)) {
                throw new IllegalStateException("Certificate not found for alias: " + properties.getKeyAlias());
            }

            PublicKey publicKey = x509Certificate.getPublicKey();
            return new SignatureKeyMaterial(privateKey, publicKey, x509Certificate);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load signature keys from keystore", ex);
        }
    }

    // Открывает поток keystore из classpath/file URL или обычного пути файловой системы.
    private InputStream openKeyStoreStream(String keyStorePath) throws Exception {
        if (keyStorePath.startsWith("classpath:") || keyStorePath.startsWith("file:")) {
            Resource resource = new DefaultResourceLoader().getResource(keyStorePath);
            return resource.getInputStream();
        }

        return Files.newInputStream(Path.of(keyStorePath));
    }

    // Проверяет обязательные параметры, без которых модуль ЭЦП работать не сможет.
    private void validateRequiredProperties() {
        if (isBlank(properties.getKeyStorePath())) {
            throw new IllegalStateException("signature.key-store-path is required");
        }

        if (isBlank(properties.getKeyStorePassword())) {
            throw new IllegalStateException("signature.key-store-password is required");
        }

        if (isBlank(properties.getKeyAlias())) {
            throw new IllegalStateException("signature.key-alias is required");
        }
    }

    // Возвращает пароль ключа; если не задан, использует пароль хранилища.
    private char[] resolveKeyPassword() {
        String keyPassword = properties.getKeyPassword();
        if (isBlank(keyPassword)) {
            keyPassword = properties.getKeyStorePassword();
        }
        return keyPassword.toCharArray();
    }

    // Проверяет строку на null/пустоту.
    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
