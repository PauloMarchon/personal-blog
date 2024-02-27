package com.paulomarchon.blog.authorizationserver.rsakey;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

public record RsaKeyPairDto(
        String id,
        Instant created,
        String publicKey,
        String privateKey

) implements Serializable {

}
