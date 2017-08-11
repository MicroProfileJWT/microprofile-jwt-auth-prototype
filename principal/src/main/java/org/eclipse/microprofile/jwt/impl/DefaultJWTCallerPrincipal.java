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

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import javax.security.auth.Subject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A default implementation of JWTCallerPrincipal that wraps the jose4j JwtClaims.
 * @see JwtClaims
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private String jwt;
    private String type;
    private JwtClaims claimsSet;

    /**
     * Create the DefaultJWTCallerPrincipal from the parsed JWT token and the extracted principal name
     * @param jwt - the parsed JWT token representation
     * @param name - the extracted unqiue name to use as the principal name; from "upn", "preferred_username" or "sub" claim
     */
    public DefaultJWTCallerPrincipal(String jwt, String type, JwtClaims claimsSet, String name) {
        super(name);
        this.jwt = jwt;
        this.type = type;
        this.claimsSet = claimsSet;
    }

    @Override
    public Set<String> getAudience() {
        Optional<Object> aud = claim(Claims.aud.name());
        Set<String> audSet = new HashSet<>();
        if(aud.isPresent()) {
            Object audObj = aud.get();

            if(audObj.getClass().isArray()) {
                String[] audArray = (String[]) audObj;
                audSet.addAll(Arrays.asList(audArray));
            } else {
                audSet.add((String) audObj);
            }
        } else {
            audSet = Collections.emptySet();
        }
        return audSet;
    }

    @Override
    public Set<String> getGroups() {
        HashSet<String> groups = new HashSet<>();
        try {
            List<String> globalGroups = claimsSet.getStringListClaimValue("groups");
            if (globalGroups != null) {
                groups.addAll(globalGroups);
            }
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        return groups;
    }


    @Override
    public Set<String> getClaimNames() {
        return new HashSet<>(claimsSet.getClaimNames());
    }

    @Override
    public Object getClaim(String claimName) {
        Claims claimType = Claims.UNKNOWN;
        Object claim = null;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {

        }
        // Handle the jose4j NumericDate types and
        switch (claimType) {
            case exp:
            case iat:
            case auth_time:
            case nbf:
            case updated_at:
                try {
                    claim = claimsSet.getClaimValue(claimType.name(), Long.class);
                    if(claim == null) {
                        claim = new Long(0);
                    }
                } catch (MalformedClaimException e) {
                }
                break;
            case UNKNOWN:
                claim = claimsSet.getClaimValue(claimName);
                break;
            default:
                claim = claimsSet.getClaimValue(claimType.name());
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
     *                JsonWebToken interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    @Override
    public String toString(boolean showAll) {
        String toString =  "DefaultJWTCallerPrincipal{" +
                "id='" + getTokenID() + '\'' +
                ", name='" + getName() + '\'' +
                ", expiration=" + getExpirationTime() +
                ", notBefore=" + getClaim(Claims.nbf.name()) +
                ", issuedAt=" + getIssuedAtTime() +
                ", issuer='" + getIssuer() + '\'' +
                ", audience=" + getAudience() +
                ", subject='" + getSubject() + '\'' +
                ", type='" + type + '\'' +
                ", issuedFor='" + getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_username") + '\'' +
                ", email='" + getClaim("email") + '\'' +
                ", emailVerified=" + getClaim( Claims.email_verified.name()) +
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
