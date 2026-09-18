package com.panicpause.panic_pause.dto;

public record ScanResponse(
        String riskLevel, // Will be "HIGH", "MEDIUM", or "LOW"
        int confidenceScore,
        String scamType,
        String explanation,
        String advice
) {}
