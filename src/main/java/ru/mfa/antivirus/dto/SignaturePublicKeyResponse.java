package ru.mfa.antivirus.dto;

public class SignaturePublicKeyResponse {
    private String algorithm;
    private String publicKeyBase64;
    private String certificatePem;
    private long ticketTtlSeconds;

    public SignaturePublicKeyResponse() {
    }

    public SignaturePublicKeyResponse(String algorithm, String publicKeyBase64, String certificatePem,
            long ticketTtlSeconds) {
        this.algorithm = algorithm;
        this.publicKeyBase64 = publicKeyBase64;
        this.certificatePem = certificatePem;
        this.ticketTtlSeconds = ticketTtlSeconds;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public void setPublicKeyBase64(String publicKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
    }

    public String getCertificatePem() {
        return certificatePem;
    }

    public void setCertificatePem(String certificatePem) {
        this.certificatePem = certificatePem;
    }

    public long getTicketTtlSeconds() {
        return ticketTtlSeconds;
    }

    public void setTicketTtlSeconds(long ticketTtlSeconds) {
        this.ticketTtlSeconds = ticketTtlSeconds;
    }
}
