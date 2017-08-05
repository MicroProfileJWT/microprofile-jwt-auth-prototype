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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;

import javax.security.auth.Subject;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A default implementation of JWTCallerPrincipal that wraps the nimbus SignedJWT.
 * @see SignedJWT
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private static Set<String> OTHER_CLAIM_NAMES;
    static {
        // Initialize the other claim names to some of the key ones in OIDC/OAuth2 but not MP JWT
        Set<String> tmp = new HashSet<>();
        tmp.add("nbf");
        tmp.add("auth_time");
        tmp.add("azp");
        tmp.add("nonce");
        tmp.add("acr");
        tmp.add("at_hash");
        tmp.add("name");
        tmp.add("given_name");
        tmp.add("family_name");
        tmp.add("email");
        tmp.add("email_verified");
        tmp.add("zoneinfo");
        tmp.add("website");
        tmp.add("preferred_username");
        tmp.add("updated_at");
        OTHER_CLAIM_NAMES = Collections.unmodifiableSet(tmp);
    }
    //private MPAccessToken jwt;
    private SignedJWT jwt;
    private JWTClaimsSet claimsSet;

    /**
     * Create the DefaultJWTCallerPrincipal from the parsed JWT token and the extracted principal name
     * @param jwt - the parsed JWT token representation
     * @param name - the extracted unqiue name to use as the principal name; from "upn", "preferred_username" or "sub" claim
     */
    public DefaultJWTCallerPrincipal(SignedJWT jwt, JWTClaimsSet claimsSet, String name) {
        super(name);
        this.jwt = jwt;
        this.claimsSet = claimsSet;
    }

    @Override
    public String getRawToken() {
        return jwt.getParsedString();
    }

    @Override
    public String getIssuer() {
        return claimsSet.getIssuer();
    }

    @Override
    public Set<String> getAudience() {
        List<String> aud = claimsSet.getAudience();
        HashSet<String> audSet = new HashSet<>();
        audSet.addAll(aud);
        return audSet;
    }

    @Override
    public String getSubject() {
        return claimsSet.getSubject();
    }

  @Override
    public String getTokenID() {
        return claimsSet.getJWTID();
    }

    @Override
    public long getExpirationTime() {
        return claimsSet.getExpirationTime().getTime() / 1000;
    }

    @Override
    public long getIssuedAtTime() {
        return claimsSet.getIssueTime().getTime() / 1000;
    }

    @Override
    public Set<String> getGroups() {
        HashSet<String> groups = new HashSet<>();
        try {
            List<String> globalGroups = claimsSet.getStringListClaim("groups");
            if (globalGroups != null) {
                groups.addAll(globalGroups);
            }
        } catch (ParseException e) {
        }
        return groups;
    }

    /**
     * Access the standard but non-MP mandated claim names this token may have. Note that the token may have even more
     * custom claims avaialable via the {@link #getClaim(String)} method.
     * @return standard but non-MP mandated claim names this token may have.
     */
    @Override
    public Set<String> getClaimNames() {
        return OTHER_CLAIM_NAMES;
    }

    @Override
    public Object getClaim(String claimName) {
        Object claim = null;
        switch (claimName) {
            case "exp":
                claim = getExpirationTime();
                break;
            case "iat":
                claim = getIssuedAtTime();
                break;
            default:
                claim = claimsSet.getClaim(claimName);
        }
        return claim;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    public String toString() {
        return toString(false);
    }
    /**
     * TODO: showAll is ignored and currently assumed true
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JWTPrincipal interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    @Override
    public String toString(boolean showAll) {
        String toString =  "DefaultJWTCallerPrincipal{" +
                "id='" + getTokenID() + '\'' +
                ", name='" + getName() + '\'' +
                ", expiration=" + getExpirationTime() +
                ", notBefore=" + getClaim("nbf") +
                ", issuedAt=" + getIssuedAtTime() +
                ", issuer='" + getIssuer() + '\'' +
                ", audience=" + getAudience() +
                ", subject='" + getSubject() + '\'' +
                ", type='" + jwt.getHeader().getType() + '\'' +
                ", issuedFor='" + claimsSet.getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_name") + '\'' +
                ", email='" + getClaim("email") + '\'' +
                ", emailVerified=" + getClaim("emailVerified") +
                ", allowedOrigins=" + getClaim("allowedOrigins") +
                ", updatedAt=" + getClaim("updated_at") +
                ", acr='" + getClaim("acr") + '\''
                ;
        StringBuilder tmp = new StringBuilder(toString);
        tmp.append(", groups=[");
        for(String group : getGroups()) {
            tmp.append(group);
            tmp.append(',');
        }
        tmp.setLength(tmp.length()-1);
        tmp.append("]}");
        return tmp.toString();
    }

}
