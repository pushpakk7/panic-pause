package com.panicpause.panic_pause.dto;

public record ScanRequest(
        String text,
        String imageBase64
) {}