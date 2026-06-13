package org.springdemo.debuggers_blockchain.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Column;
import jakarta.persistence.Lob;

@Entity
@Table(name = "CSBC_BLOCKCHAIN_LEDGER")
public class LedgerEntity {

    @Id
    @Column(name = "DID_URI")
    private String didUri;

    @Lob
    @Column(name = "PUBLIC_KEY_BASE64")
    private String publicKeyBase64;

    // Standard Getters and Setters
}
