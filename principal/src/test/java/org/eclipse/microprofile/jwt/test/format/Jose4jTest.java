package org.eclipse.microprofile.jwt.test.format;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.testng.annotations.Test;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

public class Jose4jTest {
    @Test
    public void testBigDouble() throws Exception {
        String content = "{\"customDouble\": 3.14159265358979323846}";
        System.out.printf("Input: %s\n", content);
        JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
        JSONObject jwtContent = (JSONObject) parser.parse(content);
        System.out.printf("Output: %s\n", jwtContent.toJSONString());
    }
    @Test
    public void parseRolesEndpoint() throws Exception {
        PublicKey publicKey = org.eclipse.microprofile.jwt.tck.util.TokenUtils.readPublicKey("/publicKey.pem");
        if(publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setSkipAllValidators()
                .setVerificationKey(publicKey)
                ;
        HashMap<String, Long> timeClaims = new HashMap<>();
        //String token = org.eclipse.microprofile.jwt.tck.util.TokenUtils.generateTokenString("/RolesEndpoint.json", null, timeClaims);
        String token = org.eclipse.microprofile.jwt.tck.util.TokenUtils.generateTokenString("/RolesEndpoint.json");
        JwtConsumer jwtConsumer = builder.build();
        JwtContext jwtContext = jwtConsumer.process(token);
        //  Validate the JWT and process it to the Claims
        jwtConsumer.processContext(jwtContext);
        JwtClaims claimsSet = jwtContext.getJwtClaims();
        for(String name : claimsSet.getClaimNames()) {
            Object value = claimsSet.getClaimValue(name);
            System.out.printf("%s: %s[%s]\n", name, value, value.getClass());
        }

        Object customObject = claimsSet.getClaimValue("customObject");
        JsonObject jsonObject = replaceMap((Map<String, Object> )customObject);
        System.out.println(jsonObject);
    }

    private JsonObject replaceMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for(Map.Entry<String,Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if(entryValue instanceof Map) {
                JsonObject entryJsonObject = replaceMap((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if(entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if(entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if(entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if(entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if(entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }
    private JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if(value instanceof Number) {
            Number number = (Number) value;
            if((number instanceof Long) || (number instanceof Integer)) {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.longValue())
                        .build()
                        .getJsonNumber("tmp");
            } else {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.doubleValue())
                        .build()
                        .getJsonNumber("tmp");
            }
        }
        else if(value instanceof Boolean) {
            Boolean flag = (Boolean) value;
            jsonValue = flag ? JsonValue.TRUE : JsonValue.FALSE;
        }
        else if(value instanceof List) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            List list = (List) value;
            for(Object element : list) {
                if(element instanceof String) {
                    arrayBuilder.add(element.toString());
                }
                else {
                    JsonValue jvalue = wrapValue(element);
                    arrayBuilder.add(jvalue);
                }
            }
            jsonValue = arrayBuilder.build();
        }
        return jsonValue;
    }
}
