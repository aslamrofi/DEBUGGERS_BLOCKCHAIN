package org.springdemo.debuggers_blockchain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DebuggersBlockchainApplication {

    public static void main(String[] args) {
        SpringApplication.run(DebuggersBlockchainApplication.class, args);
    }

    // Add this method to provide the ObjectMapper bean manually
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}