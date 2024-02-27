package com.paulomarchon.blog.authorizationserver.rsakey.converter;

import com.paulomarchon.blog.authorizationserver.exception.RsaKeyPairNotFoundException;
import com.paulomarchon.blog.authorizationserver.rsakey.RsaKeyPair;
import com.paulomarchon.blog.authorizationserver.rsakey.RsaKeyPairDto;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class RsaKeyPairConverter {
    private final RsaPublicKeyConverter publicKeyConverter;
    private final RsaPrivateKeyConverter privateKeyConverter;

    public RsaKeyPairConverter(RsaPublicKeyConverter publicKeyConverter, RsaPrivateKeyConverter privateKeyConverter) {
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
    }

    public RsaKeyPairDto toDto(RsaKeyPair rsaKeyPair) {
        try(ByteArrayOutputStream publicBaos = new ByteArrayOutputStream();
            ByteArrayOutputStream privateBaos = new ByteArrayOutputStream()) {
            this.publicKeyConverter.serialize(rsaKeyPair.getPublicKey(), publicBaos);
            this.privateKeyConverter.serialize(rsaKeyPair.getPrivateKey(), privateBaos);
                return new RsaKeyPairDto(
                        rsaKeyPair.getId(),
                        rsaKeyPair.getCreated(),
                        publicBaos.toString(),
                        privateBaos.toString()
                );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public RsaKeyPair toRsaKeyPair(RsaKeyPairDto vo) {
        if(vo == null)
            throw new RsaKeyPairNotFoundException();
        try {
            byte[] publicKeyBytes = vo.publicKey().getBytes();
            byte[] privateKeyBytes = vo.privateKey().getBytes();
            RSAPublicKey publicKey = this.publicKeyConverter.deserializeFromByteArray(publicKeyBytes);
            RSAPrivateKey privateKey = this.privateKeyConverter.deserializeFromByteArray(privateKeyBytes);
            return new RsaKeyPair(
                vo.id(),
                vo.created(),
                publicKey,
                privateKey
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
