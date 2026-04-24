package ru.mfa.antivirus.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.mfa.antivirus.model.Device;
import ru.mfa.antivirus.model.DeviceLicense;
import ru.mfa.antivirus.model.License;

import java.util.Optional;

@Repository
public interface DeviceLicenseRepository extends JpaRepository<DeviceLicense, Long> {
    long countByLicense_Id(Long licenseId);

    boolean existsByLicenseAndDevice(License license, Device device);

    Optional<DeviceLicense> findByLicenseAndDevice(License license, Device device);
}
