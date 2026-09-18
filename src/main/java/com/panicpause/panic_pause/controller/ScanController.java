package com.panicpause.panic_pause.controller;

import com.panicpause.panic_pause.dto.ScanRequest;
import com.panicpause.panic_pause.dto.ScanResponse;
import com.panicpause.panic_pause.service.ScamDetectorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScamDetectorService scamDetectorService;

    public ScanController(ScamDetectorService scamDetectorService) {
        this.scamDetectorService = scamDetectorService;
    }

    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> scanMessage(@RequestBody ScanRequest request) {
        // Validation: If both text and image are empty, reject it.
        if ((request.text() == null || request.text().trim().isEmpty()) &&
                (request.imageBase64() == null || request.imageBase64().isEmpty())) {
            return ResponseEntity.badRequest().build();
        }

        // Pass to the service and return the result
        ScanResponse response = scamDetectorService.analyze(request);
        return ResponseEntity.ok(response);
    }
}