package ru.mfa.antivirus.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.mfa.antivirus.model.License;

import java.time.OffsetDateTime;
import java.util.Optional;

@Repository
public interface LicenseRepository extends JpaRepository<License, Long> {
    Optional<License> findByCode(String code);

    boolean existsByCode(String code);

    @Query("""
            select l from License l
            join DeviceLicense dl on dl.license = l
            where dl.device.id = :deviceId
              and l.user.id = :userId
              and l.product.id = :productId
              and l.blocked = false
              and l.product.blocked = false
              and l.endingDate >= :now
            """)
    Optional<License> findActiveForCheck(@Param("deviceId") Long deviceId,
            @Param("userId") Long userId,
            @Param("productId") Long productId,
            @Param("now") OffsetDateTime now);
}
