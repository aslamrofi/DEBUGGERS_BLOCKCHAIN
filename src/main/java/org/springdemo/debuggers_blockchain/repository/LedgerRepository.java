package org.springdemo.debuggers_blockchain.repository;

// CHANGE THIS LINE:
import org.springdemo.debuggers_blockchain.model.LedgerEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LedgerRepository extends JpaRepository<LedgerEntity, String> {
}