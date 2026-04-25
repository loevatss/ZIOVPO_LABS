package ru.mfa.antivirus.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.mfa.antivirus.dto.SignatureIdsRequest;
import ru.mfa.antivirus.service.BinarySignatureService;

import java.time.Instant;

@RestController
@RequestMapping("/api/binary/signatures")
public class BinarySignatureController {
    private final BinarySignatureService binarySignatureService;

    public BinarySignatureController(BinarySignatureService binarySignatureService) {
        this.binarySignatureService = binarySignatureService;
    }

    // Отдает полный бинарный дамп в multipart/mixed.
    @GetMapping("/full")
    public ResponseEntity<byte[]> getFull() {
        return binarySignatureService.exportFull();
    }

    // Отдает бинарный инкремент после since в multipart/mixed.
    @GetMapping("/increment")
    public ResponseEntity<byte[]> getIncrement(@RequestParam Instant since) {
        return binarySignatureService.exportIncrement(since);
    }

    // Отдает бинарный пакет по списку UUID в multipart/mixed.
    @PostMapping("/by-ids")
    public ResponseEntity<byte[]> getByIds(@Valid @RequestBody SignatureIdsRequest request) {
        return binarySignatureService.exportByIds(request.getIds());
    }
}
