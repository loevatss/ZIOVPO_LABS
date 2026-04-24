package ru.mfa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import ru.mfa.antivirus.signature.SignatureProperties;

@SpringBootApplication
@EnableConfigurationProperties(SignatureProperties.class)
public class AntivirusApplication {
    public static void main(String[] args) {
        SpringApplication.run(AntivirusApplication.class, args);
    }
}
