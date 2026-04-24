package ru.mfa.antivirus.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.mfa.antivirus.model.LicenseType;

@Repository
public interface LicenseTypeRepository extends JpaRepository<LicenseType, Long> {
}
