package ru.mfa.antivirus.model;

import jakarta.persistence.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "device_license", uniqueConstraints = {
        @UniqueConstraint(name = "uk_device_license", columnNames = { "license_id", "device_id" })
})
public class DeviceLicense {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "license_id")
    private License license;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "device_id")
    private Device device;

    @Column(name = "activation_date", nullable = false)
    private OffsetDateTime activationDate;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public License getLicense() {
        return license;
    }

    public void setLicense(License license) {
        this.license = license;
    }

    public Device getDevice() {
        return device;
    }

    public void setDevice(Device device) {
        this.device = device;
    }

    public OffsetDateTime getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(OffsetDateTime activationDate) {
        this.activationDate = activationDate;
    }
}
