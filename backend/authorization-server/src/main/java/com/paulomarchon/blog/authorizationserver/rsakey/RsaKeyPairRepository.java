package com.paulomarchon.blog.authorizationserver.rsakey;

import java.util.List;

public interface RsaKeyPairRepository  {
    List<RsaKeyPair> findKeyPairs();
    RsaKeyPair findRsaKeyPair(String id);
    void save(RsaKeyPair rsaKeyPair);
    void deleteById(String id);
    void deleteAll();
}
