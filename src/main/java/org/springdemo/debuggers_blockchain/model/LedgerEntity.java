package org.springdemo.debuggers_blockchain.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "CSBC_BLOCKCHAIN_LEDGER")
public class LedgerEntity {

    @Id
    @Column(name = "DID_URI")
    private String didUri;

    @Lob
    @Column(name = "PUBLIC_KEY_BASE64")
    private String publicKeyBase64;

    @Column(name = "CREATED_AT", insertable = false, updatable = false)
    private LocalDateTime createdAt;

    // Constructors
    public LedgerEntity() {}

    public LedgerEntity(String didUri, String publicKeyBase64) {
        this.didUri = didUri;
        this.publicKeyBase64 = publicKeyBase64;
    }

    // Getters and Setters
    public String getDidUri() { return didUri; }
    public void setDidUri(String didUri) { this.didUri = didUri; }

    public String getPublicKeyBase64() { return publicKeyBase64; }
    public void setPublicKeyBase64(String publicKeyBase64) { this.publicKeyBase64 = publicKeyBase64; }

    public LocalDateTime getCreatedAt() { return createdAt; }
}