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

    // Step 1: Issuer creates identity AND returns the locked signature for the original data
    @PostMapping("/register")
    public ResponseEntity<?> registerIdentity(
            @RequestParam String didUri,
            @RequestBody String customJsonData) { // <--- Accepts JSON from the website now
        try {
            // 1. Generate keys and save the public key anchor to Oracle 19c
            String privateKeyBase64 = identityService.createSovereignIdentity(didUri);

            // 2. Clean up any hidden whitespace from the web transmission
            String normalizedJson = customJsonData.trim().replace("\r\n", "\n");

            // 3. Generate the locked cryptographic signature using the website's data payload
            String initialSignature = identityService.signIdentityPayload(normalizedJson, privateKeyBase64);

            return ResponseEntity.ok(Map.of(
                    "status", "Registered on Ledger",
                    "did", didUri,
                    "private_wallet_key", privateKeyBase64,
                    "official_immutable_signature", initialSignature
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getLocalizedMessage());
        }
    }

    // Step 2: Strict mathematical verification (No hardcoded values!)
    @PostMapping("/verify")
    public ResponseEntity<String> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody String rawJsonData) {
        try {
            String normalizedJson = rawJsonData.trim().replace("\r\n", "\n");

            // Run pure cryptographic math against the Oracle public key registry
            boolean fitsVerification = identityService.verifyIdentityClaim(normalizedJson, signature, didUri);

            if (fitsVerification) {
                return ResponseEntity.ok("Verification Successful: Trusted Identity Authenticated.");
            } else {
                return ResponseEntity.status(401).body("Security Alert: Cryptographic signature is broken! Data has been maliciously modified.");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Processing Error: " + e.getLocalizedMessage());
        }
    }
}