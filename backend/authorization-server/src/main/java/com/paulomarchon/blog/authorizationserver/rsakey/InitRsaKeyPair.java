package com.paulomarchon.blog.authorizationserver.rsakey;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

@Component
public class InitRsaKeyPair implements ApplicationRunner {
    private final RsaKeyPairRepository repository;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public InitRsaKeyPair(RsaKeyPairRepository repository,
                           @Value("${jwt.key.public}") RSAPublicKey publicKey,
                           @Value("${jwt.key.private}") RSAPrivateKey privateKey) {
        this.repository = repository;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        repository.deleteAll();

        RsaKeyPair rsaKeyPair = new RsaKeyPair(
                UUID.randomUUID().toString(),
                Instant.now(),
                publicKey,
                privateKey
        );
        repository.save(rsaKeyPair);

        for (RsaKeyPair keyPair : repository.findKeyPairs()) {
            System.out.println(keyPair);
        }
    }
}
