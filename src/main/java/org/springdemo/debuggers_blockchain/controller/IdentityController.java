package org.springdemo.debuggers_blockchain.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springdemo.debuggers_blockchain.service.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/identity")
public class IdentityController {

    @Autowired
    private IdentityService identityService;

    @Autowired
    private ObjectMapper objectMapper; // Spring Boot auto-configures this Jackson mapper

    @PostMapping("/register")
    public ResponseEntity<?> registerIdentity(
            @RequestParam String didUri,
            @RequestBody Map<String, String> payload) {
        try {
            // 1. Build a streamlined JSON string containing ONLY name and cgpa
            String simplifiedJson = String.format("{\"name\": \"%s\", \"cgpa\": \"%s\"}",
                    payload.get("name"), payload.get("cgpa"));

            // Canonicalize using Jackson to eliminate whitespace discrepancies
            JsonNode jsonNode = objectMapper.readTree(simplifiedJson);
            String canonicalJson = objectMapper.writeValueAsString(jsonNode);

            // 2. Generate asymmetric keys and commit the public key anchor to Oracle 19c
            String privateKeyBase64 = identityService.createSovereignIdentity(didUri);

            // 3. Digitally sign the standardized compact dataset
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

    @GetMapping("/ledger")
    public ResponseEntity<?> getAllLedgerEntries() {
        try {
            // This method should call a service that runs:
            // SELECT did_uri, public_key_base64 FROM CSBC_BLOCKCHAIN_LEDGER
            List<Map<String, String>> allEntries = identityService.getAllRegisteredIdentities();
            return ResponseEntity.ok(allEntries);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to retrieve ledger.");
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody String rawJsonData) {
        try {
            // Canonicalize data
            JsonNode jsonNode = objectMapper.readTree(rawJsonData);
            String canonicalJson = objectMapper.writeValueAsString(jsonNode);

            // Run math verification against Oracle public key
            boolean fitsVerification = identityService.verifyIdentityClaim(canonicalJson, signature, didUri);

            // Compute the current hash to send back to the user
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(canonicalJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            String currentHash = hexString.toString();

            if (fitsVerification) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Verification Successful: Trusted Identity Authenticated.",
                        "originalHash", currentHash,
                        "currentHash", currentHash
                ));
            } else {
                // CRITICAL: Even on failure, resolve what the expected original hash *should* have been
                // By extracting the hash verification target
                String expectedOriginalHash = identityService.getOriginalHashFromSignature(signature, didUri);

                return ResponseEntity.status(401).body(Map.of(
                        "success", false,
                        "message", "Security Alert: Cryptographic signature is broken!",
                        "originalHash", expectedOriginalHash,
                        "currentHash", currentHash
                ));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Processing Error"));
        }
    }
}