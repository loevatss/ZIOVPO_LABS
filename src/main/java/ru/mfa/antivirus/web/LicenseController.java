package ru.mfa.antivirus.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import ru.mfa.antivirus.dto.*;
import ru.mfa.antivirus.exception.NotFoundException;
import ru.mfa.antivirus.model.User;
import ru.mfa.antivirus.repository.UserRepository;
import ru.mfa.antivirus.service.LicenseService;
import ru.mfa.antivirus.service.TicketSignatureService;

import java.util.List;

@RestController
@RequestMapping("/api/licenses")
public class LicenseController {
    private final LicenseService licenseService;
    private final TicketSignatureService ticketSignatureService;
    private final UserRepository userRepository;

    public LicenseController(LicenseService licenseService,
            TicketSignatureService ticketSignatureService,
            UserRepository userRepository) {
        this.licenseService = licenseService;
        this.ticketSignatureService = ticketSignatureService;
        this.userRepository = userRepository;
    }

    // Отдает каталог продуктов для лицензирования.
    @GetMapping("/catalog/products")
    public List<ProductCatalogResponse> getProducts() {
        return licenseService.getProductCatalog();
    }

    // Отдает каталог типов лицензий с длительностями.
    @GetMapping("/catalog/types")
    public List<LicenseTypeCatalogResponse> getLicenseTypes() {
        return licenseService.getLicenseTypeCatalog();
    }

    // Публикует публичный ключ для проверки ЭЦП тикета.
    @GetMapping("/signature/public-key")
    public SignaturePublicKeyResponse getPublicKey() {
        return ticketSignatureService.getPublicKeyResponse();
    }

    // Создает лицензию (доступно только администратору).
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<LicenseResponse> createLicense(@Valid @RequestBody CreateLicenseRequest request,
            Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        return ResponseEntity.status(201).body(licenseService.createLicense(request, currentUser));
    }

    // Активирует лицензию на устройстве текущего пользователя.
    @PostMapping("/activate")
    public ResponseEntity<TicketResponse> activateLicense(@Valid @RequestBody ActivateLicenseRequest request,
            Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        return ResponseEntity.ok(licenseService.activateLicense(request, currentUser));
    }

    // Проверяет активность лицензии на устройстве и продукте.
    @PostMapping("/check")
    public ResponseEntity<TicketResponse> checkLicense(@Valid @RequestBody CheckLicenseRequest request,
            Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        return ResponseEntity.ok(licenseService.checkLicense(request, currentUser));
    }

    // Продлевает лицензию текущего пользователя.
    @PostMapping("/renew")
    public ResponseEntity<TicketResponse> renewLicense(@Valid @RequestBody RenewLicenseRequest request,
            Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        return ResponseEntity.ok(licenseService.renewLicense(request, currentUser));
    }

    // Загружает пользователя из БД по имени из токена.
    private User getCurrentUser(Authentication authentication) {
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new NotFoundException("Authenticated user not found"));
    }
}
