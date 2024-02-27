package com.paulomarchon.blog.authorizationserver.rsakey;

import com.paulomarchon.blog.authorizationserver.rsakey.converter.RsaKeyPairConverter;
import jakarta.annotation.Resource;
import org.springframework.boot.autoconfigure.cache.CacheProperties;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class RedisRsaKeyPairRepository implements RsaKeyPairRepository {
    private final String hashReference = "RsaKeyPair";
    private final RsaKeyPairConverter keyPairConverter;
    @Resource(name = "redisTemplate")
    private HashOperations<String, String, RsaKeyPairDto> hashOperations;

    public RedisRsaKeyPairRepository(RsaKeyPairConverter keyPairConverter) {
        this.keyPairConverter = keyPairConverter;
    }

    @Override
    public List<RsaKeyPair> findKeyPairs() {
        Map<String, RsaKeyPairDto> keyPairDtoMap = hashOperations.entries(hashReference);

        return keyPairDtoMap.values().stream()
                .map(keyPairConverter::toRsaKeyPair)
                .sorted(Comparator.comparing(RsaKeyPair::getCreated).reversed())
                .collect(Collectors.toList());
    }

    @Override
    public RsaKeyPair findRsaKeyPair(String id) {
        RsaKeyPairDto keyPairDto = hashOperations.get(hashReference, id);

        return keyPairConverter.toRsaKeyPair(keyPairDto);
    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        RsaKeyPairDto keyPairDto = keyPairConverter.toDto(rsaKeyPair);

        hashOperations.putIfAbsent(hashReference, keyPairDto.id(), keyPairDto);
        hashOperations.getOperations().expire(keyPairDto.id(), rsaKeyPair.getRsaKeyPairTimelife());
    }

    @Override
    public void deleteById(String id) {
        hashOperations.delete(hashReference, id);
    }

    @Override
    public void deleteAll() {
        Set<String> keys = hashOperations.getOperations().keys("*");

        for (String key : keys) {
            hashOperations.getOperations().delete(key);
        }
    }
}

