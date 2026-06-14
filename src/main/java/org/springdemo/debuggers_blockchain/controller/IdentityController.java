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

    // Step 1: User registers their digital identifier root
    @PostMapping("/register")
    public ResponseEntity<?> registerIdentity(@RequestParam String didUri) {
        try {
            String trackingPrivateKey = identityService.createSovereignIdentity(didUri);
            return ResponseEntity.ok(Map.of(
                    "status", "Registered on Ledger",
                    "did", didUri,
                    "download_private_wallet_key", trackingPrivateKey
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Step 2: Verification Engine checks submitted credential authenticity
    @PostMapping("/verify")
    public ResponseEntity<String> verifyIdentityData(
            @RequestParam String didUri,
            @RequestParam String signature,
            @RequestBody String rawJsonData) {
        try {
            boolean fitsVerification = identityService.verifyIdentityClaim(rawJsonData, signature, didUri);
            if (fitsVerification) {
                return ResponseEntity.ok("Verification Successful: Trusted Identity Authenticated.");
            } else {
                return ResponseEntity.status(401).body("Security Alert: Credential signature is broken or tampered with!");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Processing Error: " + e.getMessage());
        }
    }
}