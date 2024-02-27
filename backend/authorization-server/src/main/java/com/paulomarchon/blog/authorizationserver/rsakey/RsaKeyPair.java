package com.paulomarchon.blog.authorizationserver.rsakey;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.io.Serializable;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

public class RsaKeyPair {
    private final String id;
    private final Instant created;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public RsaKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this(UUID.randomUUID().toString(), Instant.now(), publicKey, privateKey);
    }

    public RsaKeyPair(Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this(UUID.randomUUID().toString(), created, publicKey, privateKey);
    }

    public RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.id = id;
        this.created = created;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getId() {
        return id;
    }
    public Instant getCreated() {
        return created;
    }
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
    public Duration getRsaKeyPairTimelife() { return Duration.ofHours(12L); }

    @Override
    public String toString() {
        return "RsaKeyPair{" +
                "id='" + id + '\'' +
                ", created=" + created +
                ", publicKey=" + publicKey +
                ", privateKey=" + privateKey +
                '}';
    }
}

