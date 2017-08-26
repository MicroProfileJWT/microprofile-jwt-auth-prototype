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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.eclipse.microprofile.jwt.test.cdi.WeldJUnit4Runner;
import org.eclipse.microprofile.jwt.test.util.TokenUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Basic token parsing and validation tests
 */
@RunWith(WeldJUnit4Runner.class)
public class TestTokenValidation {

    @Inject
    private JWTAuthContextInfo authContextInfo;

    /**
     * Create a JWT token representation of the jwk-content1.json test resource and then parse it into a
     * JWTCallerPrincipal to validate the RI implementation.
     *
     * @throws Exception
     */
    @Test
    public void testRIJWTCallerPrincipal() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json", invalidFields);
        System.out.printf("jwt: %s\n", jwt);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTAuthContextInfo noExpACI = new JWTAuthContextInfo(authContextInfo);
        noExpACI.setExpGracePeriodSecs(-1);
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, noExpACI);
        System.out.printf("Parsed caller principal: %s\n", callerPrincipal.toString(true));

        // Validate the required claims
        Assert.assertEquals("raw_token", jwt, callerPrincipal.getRawToken());
        Assert.assertEquals("iss", "https://server.example.com", callerPrincipal.getIssuer());
        Assert.assertEquals("sub", "24400320", callerPrincipal.getSubject());
        Assert.assertEquals("aud", "s6BhdRkqt3", callerPrincipal.getAudience().toArray()[0]);
        Assert.assertEquals("exp", 1311281970, callerPrincipal.getExpirationTime());
        Assert.assertEquals("iat", 1311280970, callerPrincipal.getIssuedAtTime());
        Assert.assertEquals("name", "jdoe@example.com", callerPrincipal.getName());
        Assert.assertEquals("jti", "a-123", callerPrincipal.getTokenID());

        // Validate the groups
        Set<String> groups = callerPrincipal.getGroups();
        String[] expectedGroupNames = {"group1", "group2"};
        HashSet<String> missingGroups = new HashSet<>();
        for (String group : expectedGroupNames) {
            if(!groups.contains(group)) {
                missingGroups.add(group);
            }
        }
        if(missingGroups.size() > 0) {
            Assert.fail("There are missing groups: "+missingGroups);
        }

        // Validate other claims
        Object authTime = callerPrincipal.getClaim("auth_time");
        Assert.assertTrue("auth_time is a Number", authTime instanceof Number);
        Assert.assertEquals("auth_time as int is 1311280969", 1311280969, ((Number)authTime).intValue());

        String preferredName = (String) callerPrincipal.getClaim("preferred_username");
        Assert.assertEquals("preferred_username is jdoe", "jdoe", preferredName);

    }

    @Test
    public void testClaimNames() throws Exception {
        String jwt = TokenUtils.generateTokenString("/RolesEndpoint.json");
        System.out.printf("jwt: %s\n", jwt);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTAuthContextInfo noExpACI = new JWTAuthContextInfo(authContextInfo);
        noExpACI.setExpGracePeriodSecs(-1);
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, noExpACI);
        Set<String> claimNames = callerPrincipal.getClaimNames();
        System.out.println(claimNames);
        String[] expectedNames = {"iss", "jti", "sub", "preferred_username", "aud", "exp", "iat", "auth_time", "roles",
            "groups", "resource_access"};
        for(String expected : expectedNames) {
            Assert.assertTrue(expected, claimNames.contains(expected));
        }
    }

    @Test
    public void testAllClaimTypes() throws Exception {
        String jwt = TokenUtils.generateTokenString("/AllClaims.json");
        System.out.printf("jwt: %s\n", jwt);
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTAuthContextInfo noExpACI = new JWTAuthContextInfo(authContextInfo);
        noExpACI.setExpGracePeriodSecs(300);
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, noExpACI);
        ArrayList<String> errors = new ArrayList<>();
        for(Claims claim : Claims.values()) {
            if(claim == Claims.UNKNOWN)
                continue;
            Object value = callerPrincipal.getClaim(claim.name());
            if(value == null) {
                errors.add(String.format("%s has null value", claim.name()));
            } else if(!claim.getType().isAssignableFrom(value.getClass())) {
                errors.add(String.format("%s type(%s) != Claim.type(%s)", claim.name(), value.getClass(), claim.getType()));
            }
        }
        Assert.assertTrue("No bad values seen: "+errors, errors.size() == 0);
    }

    /**
     * Validate that the updates jwk-content1.json verifies against current time
     * @throws Exception
     */
    @Test
    public void testUtilsToken() throws Exception {
        long nowSec = System.currentTimeMillis() / 1000;
        String jwt = TokenUtils.generateTokenString("/jwk-content1.json");
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(jwt, authContextInfo);
        System.out.println(callerPrincipal);
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
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
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
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
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
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
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

}
