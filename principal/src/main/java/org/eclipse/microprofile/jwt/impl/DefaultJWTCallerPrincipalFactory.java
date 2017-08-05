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
package org.eclipse.microprofile.jwt.impl;

import java.util.Collections;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;

/**
 * A default implementation of the abstract JWTCallerPrincipalFactory that uses the Keycloak token parsing classes.
 */
public class DefaultJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {

    /**
     * Tries to load the JWTAuthContextInfo from CDI if the class level authContextInfo has not been set.
     */
    public DefaultJWTCallerPrincipalFactory() {
    }

    @Override
    public JWTCallerPrincipal parse(final String token, final JWTAuthContextInfo authContextInfo) throws ParseException {
        JWTCallerPrincipal principal = null;

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            // Validate the signature
            JWSVerifier verifier = new RSASSAVerifier(authContextInfo.getSignerKey());
            signedJWT.verify(verifier);
            // Validate the issuer and expiration date
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {
                String issuer = claimsSet.getIssuer();
                if (issuer == null || ! issuer.equals(authContextInfo.getIssuedBy())) {
                    throw new BadJWTException("Invalid token issuer");
                }
                if(authContextInfo.getExpGracePeriodSecs() > 0) {
                    Date expMS = null;
                    try {
                        // Nimbus coverts exp to a Date
                        expMS = claimsSet.getDateClaim("exp");
                    } catch (java.text.ParseException e) {
                        throw new BadJWTException("Failed to get exp claim", e);
                    }
                    long now = System.currentTimeMillis();
                    long expUpperMS = now + authContextInfo.getExpGracePeriodSecs() * 1000;
                    // Fail if expMS is not in the past more than grace period ms
                    if (expMS.getTime() < expUpperMS) {
                        throw new BadJWTException("Token is expired");
                    }
                }
            });
            JWSKeySelector<SecurityContext> authContextKeySelector = (header, context) -> {
                if(header.getAlgorithm() != JWSAlgorithm.RS256)
                    throw new KeySourceException("RS256 algorithm no specified");
                return Collections.singletonList(authContextInfo.getSignerKey());
            };
            jwtProcessor.setJWSKeySelector(authContextKeySelector);
            jwtProcessor.process(signedJWT, null);

            // We have to determine the unique name to use as the principal name. It comes from upn, preferred_username, sub in that order
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String principalName = claimsSet.getStringClaim("upn");
            if(principalName == null) {
                principalName = claimsSet.getStringClaim("preferred_username");
                if(principalName == null) {
                    principalName = claimsSet.getSubject();
                }
            }
            principal = new DefaultJWTCallerPrincipal(signedJWT, claimsSet, principalName);
        }
        catch (java.text.ParseException e) {
            throw new ParseException("Failed to parse token", e);
        }
        catch (JOSEException e) {
            throw new ParseException("Failed to verify token signature", e);
        }
        catch (BadJOSEException e) {
            throw new ParseException("Failed to verify token claims", e);
        }

        return principal;
    }
}
