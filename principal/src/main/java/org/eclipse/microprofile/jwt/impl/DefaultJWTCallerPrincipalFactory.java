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

import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.JsonWebToken;

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
    public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
        JWTCallerPrincipal principal = null;
        try {

            // Verify the token
            TokenVerifier<MPAccessToken> verifier = TokenVerifier.create(token, MPAccessToken.class)
                    .publicKey(authContextInfo.getSignerKey())
                    .withChecks(new TokenVerifier.RealmUrlCheck(authContextInfo.getIssuedBy()));
            if(authContextInfo.getExpGracePeriodSecs() > 0) {
                verifier = verifier.withChecks(new ExpCheck<>(authContextInfo.getExpGracePeriodSecs()));
            }
            MPAccessToken jwt = verifier.getToken();
            verifier.verify();
            jwt.getOtherClaims().put("bearer_token", token);
            principal = new DefaultJWTCallerPrincipal(jwt);
        }
        catch (VerificationException e) {
            throw new ParseException("Failed to verify the input token", e);
        }
        return principal;
    }

    static class ExpCheck<T extends JsonWebToken> implements TokenVerifier.Predicate<T> {
        private int expGracePeriodSecs;
        ExpCheck(int expGracePeriodSecs) {
            this.expGracePeriodSecs = expGracePeriodSecs;
        }
        @Override
        public boolean test(T t) throws VerificationException {
            // Take the expiration in seconds since epoch and convert to ms
            long expMS = t.getExpiration();
            expMS *= 1000;
            long now = System.currentTimeMillis();
            long expUpperMS = now + expGracePeriodSecs*1000;
            // If expMS is in the past more than grace period ms
            return expMS > expUpperMS;
        }
    }
}
