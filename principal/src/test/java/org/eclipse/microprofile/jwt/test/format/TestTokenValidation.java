/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.eclipse.microprofile.jwt.test.format;

import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.eclipse.microprofile.jwt.test.cdi.WeldJUnit4Runner;
import org.eclipse.microprofile.jwt.test.util.TokenUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

/**
 * Basic token parsing and validation tests
 */
@RunWith(WeldJUnit4Runner.class)
public class TestTokenValidation {

    @Inject
    private JWTAuthContextInfo authContextInfo;

    /**
     * Create a token string from the jwk-content1.json test resources to understand the Keycloak representation
     * @throws Exception
     */
    @Test
    public void testJWT1() throws Exception {
        String jwt = generateTokenString("/jwk-content1.json");
        System.out.printf("jwt: %s\n", jwt);

        JWSInput input = new JWSInput(jwt);
        JsonWebToken jwtObj = input.readJsonContent(JsonWebToken.class);

        Map<String, Object> otherClaims = jwtObj.getOtherClaims();
        System.out.printf("otherClaims.keys: %s\n", otherClaims.keySet());
        List<String> roleNames = (List<String>) otherClaims.get("roles");
        System.out.printf("roles: %s\n", roleNames);
        System.out.printf("groups(%s): %s\n", otherClaims.get("groups").getClass(), otherClaims.get("groups"));
        System.out.printf("preferred_username: %s\n", otherClaims.get("preferred_username"));
        System.out.printf("unique_username: %s\n", otherClaims.get("unique_username"));
        Map<String, Object> resourceAccess = (Map<String, Object>) otherClaims.get("resource_access");
        System.out.printf("resource_access(%s): keys:%s; %s\n", resourceAccess.getClass(), resourceAccess.keySet(), resourceAccess);
        for(Map.Entry<String, Object> entry : resourceAccess.entrySet()) {
            Object value = resourceAccess.get(entry.getKey());
            System.out.printf("%s: %s(%s)\n", entry.getKey(), value, value.getClass());
        }
    }

    /**
     * Create a JWT token representation of the jwk-content1.json test resource and then parse it into a
     * JWTCallerPrincipal to validate the RI implementation.
     *
     * @throws Exception
     */
    @Test
    public void testRIJWTCallerPrincipal() throws Exception {
        String jwt = generateTokenString("/jwk-content1.json");
        System.out.printf("jwt: %s\n", jwt);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTAuthContextInfo noExpACI = new JWTAuthContextInfo(authContextInfo);
        noExpACI.setExpGracePeriodSecs(-1);
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, noExpACI);
        System.out.printf("Parsed caller principal: %s\n", callerPrincipal.toString(true));

        // Validate the required claims
        Assert.assertEquals("iss", "https://server.example.com", callerPrincipal.getIssuer());
        Assert.assertEquals("sub", "24400320", callerPrincipal.getSubject());
        Assert.assertEquals("aud", "s6BhdRkqt3", callerPrincipal.getAudience()[0]);
        Assert.assertEquals("exp", 1311281970, callerPrincipal.getExpirationTime());
        Assert.assertEquals("iat", 1311280970, callerPrincipal.getIssuedAtTime());
        Assert.assertEquals("unique_username", "jdoe@example.com", callerPrincipal.getUniqueUsername());
        Assert.assertEquals("name", "jdoe@example.com", callerPrincipal.getName());
        Assert.assertEquals("jti", "a-123", callerPrincipal.getTokenID());

        // Validate the roles
        Set<String> roles = callerPrincipal.getRoles();
        String[] expectedRoleNames = {"role-in-realm", "user", "manager", "my-service;role-in-my-service",
                "service-B;role-in-B"};
        HashSet<String> missingRoles = new HashSet<>();
        for (String role : expectedRoleNames) {
            if(!roles.contains(role)) {
                missingRoles.add(role);
            }
        }
        if(missingRoles.size() > 0) {
            Assert.fail("There are missing roles: "+missingRoles);
        }
        // Validate the groups
        Set<String> groups = callerPrincipal.getGroups();
        String[] expectedGroupNames = {"group1", "group2", "my-service;group1", "my-service;group2",
                "service-C;groupC", "service-C;web-tier"};
        HashSet<String> missingGroups = new HashSet<>();
        for (String group : expectedGroupNames) {
            if(!groups.contains(group)) {
                missingGroups.add(group);
            }
        }
        if(missingGroups.size() > 0) {
            Assert.fail("There are missing groups: "+missingGroups);
        }
    }

    /**
     * Validate that the updates jwk-content1.json verifies against current time
     * @throws Exception
     */
    @Test
    public void testUtilsToken() throws Exception {
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, authContextInfo);
        System.out.println(callerPrincipal);
        long nowSec = System.currentTimeMillis() / 1000;
        long iss = callerPrincipal.getIssuedAtTime();
        Assert.assertTrue(String.format("now(%d) < 1s from iss(%d)", nowSec, iss), (nowSec - iss) < 1);
        long exp = callerPrincipal.getExpirationTime();
        Assert.assertTrue(String.format("now(%d) > 299s from exp(%d)", nowSec, exp), (exp - nowSec) > 299);
    }

    /**
     * Validate that a token that is past is exp claim should fail the parse verification
     * @throws Exception - expect a ParseException
     */
    @Test()
    public void testExpiredValidation() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.EXP);
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json", invalidFields);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        try {
            JWTCallerPrincipal callerPrincipal = factory.parse(jwt, authContextInfo);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        } catch (ParseException e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    @Test
    public void testBadIssuer() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.ISSUER);
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json", invalidFields);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        try {
            JWTCallerPrincipal callerPrincipal = factory.parse(jwt, authContextInfo);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        } catch (ParseException e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    @Test
    public void testBadSigner() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.SIGNER);
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json", invalidFields);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        try {
            JWTCallerPrincipal callerPrincipal = factory.parse(jwt, authContextInfo);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        } catch (ParseException e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem
     * test resource key.
     *
     * @param jsonResName - name of test resources file
     * @return the JWT string
     * @throws IOException on parse failure
     */
    private static String generateTokenString(String jsonResName) throws IOException {
        InputStream pkIS = TestTokenValidation.class.getResourceAsStream("/privateKey.pem");
        BufferedReader bis = new BufferedReader(new InputStreamReader(pkIS));
        String privateKeyPem = bis.readLine();
        PrivateKey pk = PemUtils.decodePrivateKey(privateKeyPem);
        InputStream contentIS = TestTokenValidation.class.getResourceAsStream(jsonResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        byte[] content = new byte[length];
        System.arraycopy(tmp, 0, content, 0, length);
        String jwt = new JWSBuilder()
                .type("Bearer")
                .kid("privateKey.pem")
                .content(content)
                .rsa256(pk);
        return jwt;
    }

    /**
     * Utility main entry point to generate a new public/private key pair
     * @param args
     */
    public static void main(String[] args) {
        KeyPair kp = KeyUtils.generateRsaKeyPair(1024);
        String publilcKeyPem = PemUtils.encodeKey(kp.getPublic());
        String privateKeyPem = PemUtils.encodeKey(kp.getPrivate());
        System.out.printf("publicKey: %s\n", publilcKeyPem);
        System.out.printf("privateKeyPem: %s\n", privateKeyPem);
    }

}
