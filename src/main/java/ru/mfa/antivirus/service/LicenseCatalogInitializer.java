package ru.mfa.antivirus.service;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import ru.mfa.antivirus.model.LicenseType;
import ru.mfa.antivirus.model.Product;
import ru.mfa.antivirus.repository.LicenseTypeRepository;
import ru.mfa.antivirus.repository.ProductRepository;

@Component
public class LicenseCatalogInitializer implements CommandLineRunner {
    private final ProductRepository productRepository;
    private final LicenseTypeRepository licenseTypeRepository;

    public LicenseCatalogInitializer(ProductRepository productRepository,
            LicenseTypeRepository licenseTypeRepository) {
        this.productRepository = productRepository;
        this.licenseTypeRepository = licenseTypeRepository;
    }

    // Заполняет справочники минимальными данными, если они пустые.
    @Override
    public void run(String... args) {
        seedProducts();
        seedLicenseTypes();
    }

    // Создает стартовый продукт для тестирования лицензий.
    private void seedProducts() {
        if (productRepository.count() > 0) {
            return;
        }

        productRepository.save(new Product("Antivirus Pro", false));
    }

    // Создает базовые типы лицензий с разной длительностью.
    private void seedLicenseTypes() {
        if (licenseTypeRepository.count() > 0) {
            return;
        }

        licenseTypeRepository.save(new LicenseType("TRIAL", 7, "Trial for one week"));
        licenseTypeRepository.save(new LicenseType("MONTH", 30, "Monthly subscription"));
        licenseTypeRepository.save(new LicenseType("YEAR", 365, "Yearly subscription"));
    }
}
