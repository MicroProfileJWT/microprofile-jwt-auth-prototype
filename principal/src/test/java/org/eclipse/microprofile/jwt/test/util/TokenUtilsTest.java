package org.eclipse.microprofile.jwt.test.util;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.SecureRandom;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.testng.annotations.Test;

import static org.eclipse.microprofile.jwt.test.util.TokenUtils.readPrivateKey;

public class TokenUtilsTest {
    @Test
    public void TestHS256() throws Exception {
        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.probablePrime(256, random);
        Key key = new HmacKey(secret.toByteArray());
        JwtClaims claims = JwtClaims.parse("{\"sub\":\"jdoe\", \"customDouble\": 3.14159265358979323846}");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setHeader("typ", "JWT");
        jws.setKeyIdHeaderValue("/privateKey.pem");
        jws.setKey(key);
        jws.setPayload(claims.toJson());
        String jwt = jws.getCompactSerialization();
        System.out.println(jwt);
    }
}

