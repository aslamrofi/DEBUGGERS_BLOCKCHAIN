package org.springdemo.debuggers_blockchain.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Autowired
    private ObjectMapper objectMapper; // Spring Boot auto-configures this Jackson mapper

    @PostMapping("/register")
    public ResponseEntity<?> registerIdentity(
            @RequestParam String didUri,
            @RequestBody String customJsonData) {
        try {
            // 1. CANONICALIZATION: Parse and serialize to strip all formatting/newlines/spaces
            JsonNode jsonNode = objectMapper.readTree(customJsonData);
            String canonicalJson = objectMapper.writeValueAsString(jsonNode);

            // 2. Generate keys and anchor public key to Oracle 19c
            String privateKeyBase64 = identityService.createSovereignIdentity(didUri);

            // 3. Sign the exact CANONICAL string
            String initialSignature = identityService.signIdentityPayload(canonicalJson, privateKeyBase64);

            return ResponseEntity.ok(Map.of(
                    "status", "Registered on Ledger",
                    "did", didUri,
                    "private_wallet_key", privateKeyBase64,
                    "official_immutable_signature", initialSignature
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Registration Error: " + e.getLocalizedMessage());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody String rawJsonData) {
        try {
            // 1. CANONICALIZATION: Force the incoming data to match the exact same structure style
            JsonNode jsonNode = objectMapper.readTree(rawJsonData);
            String canonicalJson = objectMapper.writeValueAsString(jsonNode);

            // 2. Run mathematical verification on the normalized text string
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