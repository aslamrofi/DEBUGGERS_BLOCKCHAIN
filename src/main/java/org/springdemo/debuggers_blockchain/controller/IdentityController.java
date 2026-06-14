package org.springdemo.debuggers_blockchain.controller;

import org.springdemo.debuggers_blockchain.service.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/identity")
public class IdentityController {

    @Autowired
    private IdentityService identityService;
    @Autowired
    private ObjectMapper objectMapper;

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
    public ResponseEntity<?> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody Map<String, String> payload) { // 🌟 Receive as Map to extract "id"
        try {
            // 1. Extract the ID from the JSON payload sent by the frontend
            String studentId = payload.get("id");
            String jsonToVerify = "{\"id\":\"" + studentId + "\"}"; // Reconstruct the exact JSON string

            // 2. Run the cryptographic check against the reconstructed JSON
            boolean isValidOwner = identityService.verifyIdentityClaim(jsonToVerify, signature, didUri);

            // 3. Generate hashes for the UI Comparison Monitor
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(jsonToVerify.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            String computedHash = hexString.toString();

            if (isValidOwner) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Access Granted: Identity authenticated via Oracle Ledger.",
                        "originalHash", computedHash,
                        "currentHash", computedHash
                ));
            } else {
                return ResponseEntity.status(401).body(Map.of(
                        "success", false,
                        "message", "Security Block: Digital Signature mismatch.",
                        "originalHash", "ERROR_HASH_EXPECTED_MATCH_FAILED",
                        "currentHash", computedHash
                ));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Server processing error"));
        }
    }

    // 🌟 ADD THIS METHOD INSIDE IDENTITYCONTROLLER.JAVA 🌟
    @GetMapping("/ledger")
    public ResponseEntity<?> getOracleLedgerEntries() {
        try {
            // Calls your service layer to pull all DIDs from the database
            java.util.List<java.util.Map<String, String>> entries = identityService.getAllRegisteredIdentities();
            return ResponseEntity.ok(entries);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to read Oracle ledger registry.");
        }
    }
}