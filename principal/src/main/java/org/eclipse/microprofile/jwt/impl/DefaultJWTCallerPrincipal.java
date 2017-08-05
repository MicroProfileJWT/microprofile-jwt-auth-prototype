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
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import javax.security.auth.Subject;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A default implementation of JWTCallerPrincipal that wraps the jose4j JwtClaims.
 * @see JwtClaims
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
    public String getRawToken() {
        return jwt;
    }

    @Override
    public String getIssuer() {
        try {
            return claimsSet.getIssuer();
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Set<String> getAudience() {
        List<String> aud = null;
        try {
            aud = claimsSet.getAudience();
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        HashSet<String> audSet = new HashSet<>();
        audSet.addAll(aud);
        return audSet;
    }

    @Override
    public String getSubject() {
        try {
            return claimsSet.getSubject();
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        return null;
    }

  @Override
    public String getTokenID() {
      try {
          return claimsSet.getJwtId();
      } catch (MalformedClaimException e) {
          e.printStackTrace();
      }
      return null;
  }

    @Override
    public long getExpirationTime() {
        try {
            return claimsSet.getExpirationTime().getValue();
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public long getIssuedAtTime() {
        try {
            return claimsSet.getIssuedAt().getValue();
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
        return 0;
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
                claim = claimsSet.getClaimValue(claimName);
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
                ", type='" + type + '\'' +
                ", issuedFor='" + getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_username") + '\'' +
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
