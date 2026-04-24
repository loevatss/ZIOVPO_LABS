package ru.mfa.antivirus.dto;

import java.time.OffsetDateTime;

public class Ticket {
    private OffsetDateTime serverDate;
    private long ticketTtlSeconds;
    private OffsetDateTime licenseActivationDate;
    private OffsetDateTime licenseExpirationDate;
    private Long userId;
    private Long deviceId;
    private boolean licenseBlocked;

    public Ticket() {
    }

    public Ticket(OffsetDateTime serverDate, long ticketTtlSeconds, OffsetDateTime licenseActivationDate,
            OffsetDateTime licenseExpirationDate, Long userId, Long deviceId, boolean licenseBlocked) {
        this.serverDate = serverDate;
        this.ticketTtlSeconds = ticketTtlSeconds;
        this.licenseActivationDate = licenseActivationDate;
        this.licenseExpirationDate = licenseExpirationDate;
        this.userId = userId;
        this.deviceId = deviceId;
        this.licenseBlocked = licenseBlocked;
    }

    public OffsetDateTime getServerDate() {
        return serverDate;
    }

    public void setServerDate(OffsetDateTime serverDate) {
        this.serverDate = serverDate;
    }

    public long getTicketTtlSeconds() {
        return ticketTtlSeconds;
    }

    public void setTicketTtlSeconds(long ticketTtlSeconds) {
        this.ticketTtlSeconds = ticketTtlSeconds;
    }

    public OffsetDateTime getLicenseActivationDate() {
        return licenseActivationDate;
    }

    public void setLicenseActivationDate(OffsetDateTime licenseActivationDate) {
        this.licenseActivationDate = licenseActivationDate;
    }

    public OffsetDateTime getLicenseExpirationDate() {
        return licenseExpirationDate;
    }

    public void setLicenseExpirationDate(OffsetDateTime licenseExpirationDate) {
        this.licenseExpirationDate = licenseExpirationDate;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(Long deviceId) {
        this.deviceId = deviceId;
    }

    public boolean isLicenseBlocked() {
        return licenseBlocked;
    }

    public void setLicenseBlocked(boolean licenseBlocked) {
        this.licenseBlocked = licenseBlocked;
    }
}
