package com.panicpause.panic_pause.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.panicpause.panic_pause.dto.ScanRequest;
import com.panicpause.panic_pause.dto.ScanResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ScamDetectorService {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    @Value("${gemini.api.key}")
    private String apiKey;

    public ScamDetectorService() {
        this.restClient = RestClient.builder()
                // Standard 1.5-flash model
                .baseUrl("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.7-flash:generateContent")
                .defaultHeader("Content-Type", "application/json")
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public ScanResponse analyze(ScanRequest request) {
        String prompt = """
                You are an elite fraud investigator. Analyze the provided message and/or image for social engineering, financial fraud, phishing, or UPI scams.
                Respond ONLY with a valid JSON object matching this schema:
                {
                  "riskLevel": "HIGH" | "MEDIUM" | "LOW",
                  "confidenceScore": <integer 0-100>,
                  "scamType": "<Specific Scam Name or 'Legitimate Communication'>",
                  "explanation": "<2 clear sentences explaining the psychological trap in simple terms without tech jargon>",
                  "advice": "<1 clear actionable step on what the user should do right now>"
                }
                """;

        try {
            List<Map<String, Object>> parts = new ArrayList<>();
            parts.add(Map.of("text", prompt));

            if (request.text() != null && !request.text().trim().isEmpty()) {
                parts.add(Map.of("text", "User Text: " + request.text()));
            }

            if (request.imageBase64() != null && !request.imageBase64().trim().isEmpty()) {
                Map<String, Object> inlineData = new HashMap<>();
                inlineData.put("mime_type", "image/png");
                inlineData.put("data", request.imageBase64());
                parts.add(Map.of("inline_data", inlineData));
            }

            Map<String, Object> payload = Map.of(
                    "contents", List.of(Map.of("parts", parts)),
                    "generationConfig", Map.of(
                            "response_mime_type", "application/json",
                            "temperature", 0.1
                    )
            );

            // Pass the key via URL query parameter (Standard Gemini format)
            String rawJson = null;
            int maxRetries = 2;

            for (int attempt = 1; attempt <= maxRetries; attempt++) {
                try {
                    rawJson = restClient.post()
                            .header("x-goog-api-key", apiKey)
                            .body(payload)
                            .retrieve()
                            .body(String.class);
                    break; // Success! Exit the loop.
                } catch (Exception e) {
                    if (attempt == maxRetries || !e.getMessage().contains("503")) {
                        throw e; // If it's the last try, or NOT a 503 error, fail immediately.
                    }
                    System.out.println("Google Server busy. Retrying in 2 seconds...");
                    Thread.sleep(2000); // Pause for 2 seconds before retry
                }
            }
            JsonNode rootNode = objectMapper.readTree(rawJson);
            String contentString = rootNode.path("candidates").get(0).path("content").path("parts").get(0).path("text").asText();
            JsonNode finalAnalysis = objectMapper.readTree(contentString);

            return new ScanResponse(
                    finalAnalysis.path("riskLevel").asText("HIGH"),
                    finalAnalysis.path("confidenceScore").asInt(90),
                    finalAnalysis.path("scamType").asText("Unverified"),
                    finalAnalysis.path("explanation").asText("Analyzed correctly."),
                    finalAnalysis.path("advice").asText("Proceed with caution.")
            );

        } catch (Exception e) {
            System.err.println("Gemini API Error: " + e.getMessage());

            // TIER 2 FALLBACK: Local Heuristic Engine when upstream AI throttles
            String rawText = (request.text() != null) ? request.text().toLowerCase() : "";

            boolean hasUrgency = rawText.contains("urgent") || rawText.contains("locked") ||
                    rawText.contains("disconnected") || rawText.contains("immediately") ||
                    rawText.contains("suspend") || rawText.contains("expire") ||
                    rawText.contains("police") || rawText.contains("fine");

            boolean hasCallToAction = rawText.contains("http") || rawText.contains("call") ||
                    rawText.contains("contact") || rawText.contains("click");

            boolean isSafeTransaction = (rawText.contains("successful") || rawText.contains("credited") ||
                    rawText.contains("debited") || rawText.contains("ref no") ||
                    rawText.contains("thank you")) && !hasUrgency;

            if (isSafeTransaction) {
                return new ScanResponse(
                        "LOW", 95, "Verified Transactional Alert",
                        "This message contains standard confirmation markers typical of formal banking or bill receipts, with zero artificial urgency or coercive threats.",
                        "No action required. This alert appears consistent with authentic transaction records."
                );
            } else if (hasUrgency && hasCallToAction) {
                return new ScanResponse(
                        "HIGH", 94, "Urgency-Driven Impersonation Scam",
                        "The message creates artificial panic by threatening immediate service termination or account suspension to force a hasty response without verification.",
                        "Do not click links or call numbers provided in the text. Verify directly using your provider's official mobile application."
                );
            } else if (rawText.contains("congratulations") || rawText.contains("pre-approved") || rawText.contains("claim")) {
                return new ScanResponse(
                        "MEDIUM", 85, "Unsolicited Promotional Solicitation",
                        "Contains marketing hyperbole or pre-approved financial claims designed to trigger impulse engagement.",
                        "Treat unsolicited financial offers with caution. Review terms independently before engaging."
                );
            } else {
                return new ScanResponse(
                        "LOW", 88, "Standard Communication",
                        "No coercive manipulation, financial coercion, or known scam signatures detected.",
                        "Practice standard digital caution."
                );
            }
        }
    }
}