package ru.mfa.antivirus.dto;

import ru.mfa.antivirus.model.LicenseType;

public class LicenseTypeCatalogResponse {
    private Long id;
    private String name;
    private int defaultDurationInDays;
    private String description;

    public static LicenseTypeCatalogResponse from(LicenseType licenseType) {
        LicenseTypeCatalogResponse response = new LicenseTypeCatalogResponse();
        response.setId(licenseType.getId());
        response.setName(licenseType.getName());
        response.setDefaultDurationInDays(licenseType.getDefaultDurationInDays());
        response.setDescription(licenseType.getDescription());
        return response;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getDefaultDurationInDays() {
        return defaultDurationInDays;
    }

    public void setDefaultDurationInDays(int defaultDurationInDays) {
        this.defaultDurationInDays = defaultDurationInDays;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
