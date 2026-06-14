package org.springdemo.debuggers_blockchain.controller;

import org.springdemo.debuggers_blockchain.service.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/identity")
public class IdentityController {

    @Autowired
    private IdentityService identityService;

    // Hardcoded static token used for challenge-response auth verification
    private static final String AUTH_CHALLENGE = "AUTHENTICATION_CHALLENGE_TOKEN";

    @PostMapping("/register")
    public ResponseEntity<?> registerIdentity(
            @RequestParam String didUri,
            @RequestBody Map<String, String> payload) {
        try {
            String id = payload.get("id");

            if (id == null || !id.matches("\\d{4}")) {
                return ResponseEntity.badRequest().body("Registration Failure: ID must be exactly 4 digits.");
            }

            Map<String, String> simplifiedPayload = Map.of(
                    "id", id
            );

            String canonicalJson = objectMapper.writeValueAsString(simplifiedPayload);

            String privateKeyBase64 = identityService.createSovereignIdentity(didUri);
            String initialSignature = identityService.signIdentityPayload(canonicalJson, privateKeyBase64);

            return ResponseEntity.ok(Map.of(
                    "status", "Registered on Ledger",
                    "did", didUri,
                    "private_wallet_key", privateKeyBase64,
                    "official_immutable_signature", initialSignature
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Registration Failure: " + e.getLocalizedMessage());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody String rawJsonData) {
        try {
            JsonNode jsonNode = objectMapper.readTree(rawJsonData);

            if (!jsonNode.has("id") || !jsonNode.get("id").asText().matches("\\d{4}")) {
                return ResponseEntity.badRequest().body("Processing Error: ID must be exactly 4 digits.");
            }

            Map<String, String> simplifiedPayload = Map.of(
                    "id", jsonNode.get("id").asText()
            );

            String canonicalJson = objectMapper.writeValueAsString(simplifiedPayload);

            boolean fitsVerification = identityService.verifyIdentityClaim(canonicalJson, signature, didUri);

            if (fitsVerification) {
                return ResponseEntity.ok("Verification Successful: Trusted Identity Authenticated.");
            } else {
                return ResponseEntity.status(401).body("Security Alert: Cryptographic signature is broken! Data has been maliciously modified.");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Processing Error: Invalid JSON Format provided.");
        }
    }
}