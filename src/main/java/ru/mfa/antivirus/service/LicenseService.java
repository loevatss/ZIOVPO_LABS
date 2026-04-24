package ru.mfa.antivirus.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.mfa.antivirus.dto.*;
import ru.mfa.antivirus.exception.ConflictException;
import ru.mfa.antivirus.exception.ForbiddenOperationException;
import ru.mfa.antivirus.exception.NotFoundException;
import ru.mfa.antivirus.model.*;
import ru.mfa.antivirus.repository.*;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class LicenseService {
    private final ProductRepository productRepository;
    private final LicenseTypeRepository licenseTypeRepository;
    private final LicenseRepository licenseRepository;
    private final DeviceRepository deviceRepository;
    private final DeviceLicenseRepository deviceLicenseRepository;
    private final LicenseHistoryRepository licenseHistoryRepository;
    private final UserRepository userRepository;
    private final TicketSignatureService ticketSignatureService;

    public LicenseService(ProductRepository productRepository,
            LicenseTypeRepository licenseTypeRepository,
            LicenseRepository licenseRepository,
            DeviceRepository deviceRepository,
            DeviceLicenseRepository deviceLicenseRepository,
            LicenseHistoryRepository licenseHistoryRepository,
            UserRepository userRepository,
            TicketSignatureService ticketSignatureService) {
        this.productRepository = productRepository;
        this.licenseTypeRepository = licenseTypeRepository;
        this.licenseRepository = licenseRepository;
        this.deviceRepository = deviceRepository;
        this.deviceLicenseRepository = deviceLicenseRepository;
        this.licenseHistoryRepository = licenseHistoryRepository;
        this.userRepository = userRepository;
        this.ticketSignatureService = ticketSignatureService;
    }

    // Возвращает каталог продуктов для выбора при создании/проверке лицензии.
    @Transactional(readOnly = true)
    public List<ProductCatalogResponse> getProductCatalog() {
        return productRepository.findAll().stream()
                .map(ProductCatalogResponse::from)
                .toList();
    }

    // Возвращает каталог типов лицензий с длительностью по умолчанию.
    @Transactional(readOnly = true)
    public List<LicenseTypeCatalogResponse> getLicenseTypeCatalog() {
        return licenseTypeRepository.findAll().stream()
                .map(LicenseTypeCatalogResponse::from)
                .toList();
    }

    // Создает лицензию от имени администратора и пишет событие CREATED.
    @Transactional
    public LicenseResponse createLicense(CreateLicenseRequest request, User adminUser) {
        Product product = productRepository.findById(request.getProductId())
                .orElseThrow(() -> new NotFoundException("Product not found: " + request.getProductId()));

        LicenseType type = licenseTypeRepository.findById(request.getTypeId())
                .orElseThrow(() -> new NotFoundException("License type not found: " + request.getTypeId()));

        User owner = userRepository.findById(request.getOwnerId())
                .orElseThrow(() -> new NotFoundException("Owner user not found: " + request.getOwnerId()));

        License license = new License();
        license.setCode(generateUniqueCode());
        license.setProduct(product);
        license.setType(type);
        license.setOwner(owner);
        license.setUser(null);
        license.setFirstActivationDate(null);
        license.setEndingDate(null);
        license.setBlocked(false);
        license.setDeviceCount(resolveDeviceCount(request.getDeviceCount()));
        license.setDescription(request.getDescription());

        License saved = licenseRepository.save(license);
        saveHistory(saved, adminUser, LicenseHistoryStatus.CREATED, "License created by admin");

        return LicenseResponse.from(saved);
    }

    // Активирует лицензию на устройстве или добавляет новое устройство в рамках лимита.
    @Transactional
    public TicketResponse activateLicense(ActivateLicenseRequest request, User currentUser) {
        License license = findByCodeOrFail(request.getActivationKey());
        validateLicenseForUsage(license);

        if (license.getUser() != null && !license.getUser().getId().equals(currentUser.getId())) {
            throw new ForbiddenOperationException("License belongs to another user");
        }

        Device device = resolveDevice(request.getDeviceName(), request.getDeviceMac(), currentUser);

        if (license.getUser() == null) {
            OffsetDateTime now = OffsetDateTime.now();
            license.setUser(currentUser);
            license.setFirstActivationDate(now);
            license.setEndingDate(now.plusDays(license.getType().getDefaultDurationInDays()));
            licenseRepository.save(license);
        }

        if (!deviceLicenseRepository.existsByLicenseAndDevice(license, device)) {
            ensureDeviceLimitNotExceeded(license);
            bindDeviceToLicense(license, device);
            saveHistory(license, currentUser, LicenseHistoryStatus.ACTIVATED,
                    "License activated on device " + device.getMacAddress());
        }

        return ticketSignatureService.buildTicketResponse(license, device);
    }

    // Проверяет активность лицензии пользователя на конкретном устройстве и продукте.
    @Transactional(readOnly = true)
    public TicketResponse checkLicense(CheckLicenseRequest request, User currentUser) {
        Device device = findDeviceByMacOrFail(request.getDeviceMac());
        ensureDeviceOwnedByUser(device, currentUser);

        License license = licenseRepository.findActiveForCheck(
                device.getId(),
                currentUser.getId(),
                request.getProductId(),
                OffsetDateTime.now()).orElseThrow(() -> new NotFoundException("Active license not found for request"));

        return ticketSignatureService.buildTicketResponse(license, device);
    }

    // Продлевает лицензию при соблюдении бизнес-условия продления (<= 7 дней до окончания или уже истекла).
    @Transactional
    public TicketResponse renewLicense(RenewLicenseRequest request, User currentUser) {
        License license = findByCodeOrFail(request.getActivationKey());
        validateLicenseForUsage(license);

        if (license.getUser() == null || !license.getUser().getId().equals(currentUser.getId())) {
            throw new ForbiddenOperationException("Only activated owner can renew license");
        }

        Device device = findDeviceByMacOrFail(request.getDeviceMac());
        ensureDeviceOwnedByUser(device, currentUser);

        if (!deviceLicenseRepository.existsByLicenseAndDevice(license, device)) {
            throw new ConflictException("License is not activated on the provided device");
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime endingDate = license.getEndingDate();
        if (endingDate == null) {
            throw new ConflictException("License has no ending date to renew");
        }

        if (endingDate.isAfter(now.plusDays(7))) {
            throw new ConflictException("Renew is allowed only for expired licenses or licenses ending in 7 days");
        }

        OffsetDateTime extensionBase = endingDate.isAfter(now) ? endingDate : now;
        license.setEndingDate(extensionBase.plusDays(license.getType().getDefaultDurationInDays()));
        licenseRepository.save(license);

        saveHistory(license, currentUser, LicenseHistoryStatus.RENEWED,
                "License renewed by user");

        return ticketSignatureService.buildTicketResponse(license, device);
    }

    // Нормализует и проверяет лимит устройств по умолчанию.
    private int resolveDeviceCount(Integer requestedCount) {
        int count = requestedCount == null ? 1 : requestedCount;
        if (count < 1) {
            throw new IllegalArgumentException("Device count must be at least 1");
        }
        return count;
    }

    // Загружает лицензию по активационному ключу или бросает 404.
    private License findByCodeOrFail(String activationKey) {
        return licenseRepository.findByCode(activationKey)
                .orElseThrow(() -> new NotFoundException("License not found by activation key"));
    }

    // Проверяет, что лицензия и продукт не заблокированы.
    private void validateLicenseForUsage(License license) {
        if (license.isBlocked()) {
            throw new ConflictException("License is blocked");
        }

        if (license.getProduct().isBlocked()) {
            throw new ConflictException("Product is blocked");
        }
    }

    // Находит устройство по MAC или регистрирует новое для текущего пользователя.
    private Device resolveDevice(String deviceName, String rawMac, User currentUser) {
        String normalizedMac = normalizeMac(rawMac);

        Device existing = deviceRepository.findByMacAddress(normalizedMac).orElse(null);
        if (existing != null) {
            ensureDeviceOwnedByUser(existing, currentUser);
            if (deviceName != null && !deviceName.isBlank()) {
                existing.setName(deviceName.trim());
                return deviceRepository.save(existing);
            }
            return existing;
        }

        Device created = new Device();
        created.setName(deviceName == null || deviceName.isBlank() ? "Unnamed device" : deviceName.trim());
        created.setMacAddress(normalizedMac);
        created.setUser(currentUser);
        return deviceRepository.save(created);
    }

    // Загружает устройство по MAC-адресу или бросает 404.
    private Device findDeviceByMacOrFail(String rawMac) {
        String normalizedMac = normalizeMac(rawMac);
        return deviceRepository.findByMacAddress(normalizedMac)
                .orElseThrow(() -> new NotFoundException("Device not found by MAC"));
    }

    // Проверяет принадлежность устройства пользователю из текущего токена.
    private void ensureDeviceOwnedByUser(Device device, User currentUser) {
        if (!device.getUser().getId().equals(currentUser.getId())) {
            throw new ForbiddenOperationException("Device belongs to another user");
        }
    }

    // Проверяет, что лимит устройств по лицензии не превышен.
    private void ensureDeviceLimitNotExceeded(License license) {
        long usedDevices = deviceLicenseRepository.countByLicense_Id(license.getId());
        if (usedDevices >= license.getDeviceCount()) {
            throw new ConflictException("Device limit reached for this license");
        }
    }

    // Создает связь лицензии и устройства (факт активации).
    private void bindDeviceToLicense(License license, Device device) {
        DeviceLicense deviceLicense = new DeviceLicense();
        deviceLicense.setLicense(license);
        deviceLicense.setDevice(device);
        deviceLicense.setActivationDate(OffsetDateTime.now());
        deviceLicenseRepository.save(deviceLicense);
    }

    // Записывает событие в журнал истории лицензии.
    private void saveHistory(License license, User user, LicenseHistoryStatus status, String description) {
        LicenseHistory history = new LicenseHistory();
        history.setLicense(license);
        history.setUser(user);
        history.setStatus(status);
        history.setDescription(description);
        history.setChangeDate(OffsetDateTime.now());
        licenseHistoryRepository.save(history);
    }

    // Генерирует уникальный активационный ключ лицензии.
    private String generateUniqueCode() {
        String code;
        do {
            code = "LIC-" + UUID.randomUUID().toString().replace("-", "").toUpperCase(Locale.ROOT).substring(0, 24);
        } while (licenseRepository.existsByCode(code));

        return code;
    }

    // Нормализует MAC и валидирует формат "XX:XX:XX:XX:XX:XX".
    private String normalizeMac(String rawMac) {
        if (rawMac == null || rawMac.isBlank()) {
            throw new IllegalArgumentException("Device MAC must not be empty");
        }

        String normalized = rawMac.trim().toUpperCase(Locale.ROOT).replace('-', ':');
        if (!normalized.matches("^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")) {
            throw new IllegalArgumentException("Device MAC has invalid format");
        }

        return normalized;
    }
}
