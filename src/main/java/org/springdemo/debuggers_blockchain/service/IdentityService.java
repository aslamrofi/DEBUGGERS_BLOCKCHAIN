package org.springdemo.debuggers_blockchain.service;

import org.springdemo.debuggers_blockchain.model.LedgerEntity;
import org.springdemo.debuggers_blockchain.repository.LedgerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class IdentityService {

    @Autowired
    private LedgerRepository ledgerRepository;

    // Generates keys and registers the public identity marker directly onto the ledger
    public String createSovereignIdentity(String didUri) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        String publicKeyBase64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        // Store the public identifier on the blockchain ledger table
        LedgerEntity identityRecord = new LedgerEntity(didUri, publicKeyBase64);
        ledgerRepository.save(identityRecord);

        // Returns the private key to the user (wallet storage simulation)
        return privateKeyBase64;
    }

    // Cryptographically signs identity payload statements
    public String signIdentityPayload(String rawJson, String privateKeyBase64) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes));

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(rawJson.getBytes());

        return Base64.getEncoder().encodeToString(privateSignature.sign());
    }

    // Resolves identity markers from the database and verifies signatures
    public boolean verifyIdentityClaim(String rawJson, String signatureBase64, String didUri) throws Exception {
        LedgerEntity ledgerRecord = ledgerRepository.findById(didUri)
                .orElseThrow(() -> new RuntimeException("DID not registered on this ledger network."));

        byte[] publicKeyBytes = Base64.getDecoder().decode(ledgerRecord.getPublicKeyBase64());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(rawJson.getBytes());

        return publicSignature.verify(Base64.getDecoder().decode(signatureBase64));
    }
}