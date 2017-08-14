package org.eclipse.microprofile.jwt.test.util;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;

import org.eclipse.microprofile.jwt.Claims;

/**
 * A utility class to create json payload for a token that includes all IANA standard claims
 */
public class GenerateAllClaims {


    static void addClaimValue(Claims claim, JsonObjectBuilder json) {
        switch (claim) {
            case aud:
            case groups:
                JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                arrayBuilder.add("value1");
                arrayBuilder.add("value2");
                json.add(claim.name(), arrayBuilder);
                break;

            case exp:
            case iat:
            case auth_time:
            case updated_at:
            case at_hash:
            case c_hash:
            case nbf:
                json.add(claim.name(), System.currentTimeMillis() / 1000);
                break;

            case phone_number_verified:
            case email_verified:
                json.add(claim.name(), true);
                break;

            case iss:
            case sub:
            case jti:
            case raw_token:
            case azp:
            case nonce:
            case full_name:
            case family_name:
            case middle_name:
            case nickname:
            case given_name:
            case preferred_username:
            case email:
            case gender:
            case birthdate:
            case zoneinfo:
            case locale:
            case phone_number:
            case acr:
            case amr:
            case cnf:
            case sip_from_tag:
            case sip_date:
            case sip_callid:
            case sip_cseq_num:
            case sip_via_branch:
            case orig:
            case dest:
            case mky:
            case jwe:
            case kid:
            case jku:
                json.add(claim.name(), "stringValue-"+Math.round(Math.random()*1000000));
                break;

            case address: {
                JsonObjectBuilder address = Json.createObjectBuilder();
                address.add("street_address", "12345 Somestreet SW");
                address.add("locality", "MyCity");
                address.add("region", "WA");
                address.add("postal_code", "98908");
                address.add("country", "US");
                json.add(claim.name(), address);
                }
                break;
            case jwk: {
                JsonObjectBuilder key = Json.createObjectBuilder();
                key.add("kty", "EC");
                key.add("use", "sig");
                key.add("crv", "P-256");
                key.add("x", "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM");
                key.add("y", "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA");
                json.add(claim.name(), key);
                }
                break;
            case sub_jwk: {
                JsonObjectBuilder key = Json.createObjectBuilder();
                key.add("kty", "EC");
                key.add("kid", "Public key used in JWS A.3 example");
                key.add("crv", "P-256");
                key.add("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
                key.add("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
                json.add(claim.name(), key);
                }
                break;
        }
    }
    public static void main(String[] args) {
        JsonObjectBuilder json = Json.createObjectBuilder();
        for (Claims claim : Claims.values()) {
            addClaimValue(claim, json);
        }
        String result = json.build().toString();
        System.out.println(result);
    }
}
