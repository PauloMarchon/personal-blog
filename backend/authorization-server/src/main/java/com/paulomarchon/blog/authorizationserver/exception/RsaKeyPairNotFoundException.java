package com.paulomarchon.blog.authorizationserver.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_FOUND)
public class RsaKeyPairNotFoundException extends RuntimeException {
    public RsaKeyPairNotFoundException() {
        super("KeyPair not found!");
    }
}
