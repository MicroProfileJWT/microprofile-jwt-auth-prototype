package org.eclipse.microprofile.jwt.test.format;


import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import static org.eclipse.microprofile.jwt.test.format.TCKConstants.TEST_GROUP_JWT;
import static org.eclipse.microprofile.jwt.test.format.TCKConstants.TEST_ISSUER;

/**
 * A more extension test of the how the token JSON content types are mapped
 * to values via the JsonWebToken implementation.
 */
public class TestTokenClaimTypesTest {
    /**
     * The test generated JWT token string
     */
    private static String token;
    private static JsonWebToken jwt;
    /** */
    private static ITokenParser tokenParser;
    /** */
    private static PublicKey publicKey;

    // Time claims in the token
    private static Long iatClaim;
    private static Long authTimeClaim;
    private static Long expClaim;

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/RolesEndpoint.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());

        System.out.printf("TokenValidationTest.initClass\n");
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if(publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        // Load the ITokenParser implementation
        ServiceLoader<ITokenParser> serviceLoader = ServiceLoader.load(ITokenParser.class);
        if(serviceLoader.iterator().hasNext() == false) {
            throw new IllegalStateException(String.format("An %s service provider is required", ITokenParser.class.getName()));
        }
        tokenParser = serviceLoader.iterator().next();
        if(tokenParser == null) {
            throw new IllegalStateException(String.format("Service provider for %s  produced a null parser", ITokenParser.class.getName()));
        }
        System.out.printf("Using ITokenParser: %s\n", tokenParser);

        jwt = tokenParser.parse(token, TEST_ISSUER, publicKey);
    }

    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateRawToken() {
        Assert.assertEquals(token, jwt.getRawToken());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateIssuer() {
        Assert.assertEquals(TEST_ISSUER, jwt.getIssuer());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateSubject() {
        Assert.assertEquals("24400320", jwt.getSubject());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateTokenID() {
        Assert.assertEquals("a-123", jwt.getTokenID());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateAudience() {
        Set<String> audience = jwt.getAudience();
        HashSet<String> actual = new HashSet<>();
        actual.add("s6BhdRkqt3");
        Assert.assertEquals(actual, audience);
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateExpirationTime() {
        Assert.assertEquals(expClaim.longValue(), jwt.getExpirationTime());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateGroups() {
        Set<String> groups = jwt.getGroups();
        SortedSet<String> sortedGroups = new TreeSet<>(groups);
        SortedSet<String> actual = new TreeSet<>();
        actual.add("Echoer");
        actual.add("Tester");
        actual.add("group1");
        actual.add("group2");
        Assert.assertEquals(actual, sortedGroups);
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateIssuedAtTime() {
        Assert.assertEquals(iatClaim.longValue(), jwt.getIssuedAtTime());
    }

    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateClaimNames() {
        String[] expected = {"iss", "jti", "sub", "upn", "preferred_username",
                "aud","exp","iat", "roles","groups", "customString","customInteger",
                "customStringArray", "customIntegerArray", "customDoubleArray",
                "customObject"};
        Set<String> claimNames = jwt.getClaimNames();
        HashSet<String> missingNames = new HashSet<>();
        for (String name : expected) {
            if(!claimNames.contains(name)) {
                missingNames.add(name);
            }
        }
        Assert.assertTrue(missingNames.size() == 0, "There should be no missing claim names");
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomString() {
        String value = jwt.getClaim("customString");
        Assert.assertEquals("customStringValue", value);
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomInteger() {
        JsonNumber value = jwt.getClaim("customInteger");
        Assert.assertEquals(123456789L, value.longValue());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomDouble() {
        JsonNumber value = jwt.getClaim("customDouble");
        Assert.assertEquals(3.14159265358979323846, value.doubleValue(), 0.0000001);
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomStringArray() {
        JsonArray value = jwt.getClaim("customStringArray");
        Assert.assertEquals("value0", value.getString(0));
        Assert.assertEquals("value1", value.getString(1));
        Assert.assertEquals("value2", value.getString(2));
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomIntegerArray() {
        JsonArray value = jwt.getClaim("customIntegerArray");
        Assert.assertEquals(0, value.getInt(0));
        Assert.assertEquals(1, value.getInt(1));
        Assert.assertEquals(2, value.getInt(2));
        Assert.assertEquals(3, value.getInt(3));
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "")
    public void validateCustomDoubleArray() {
        JsonArray value = jwt.getClaim("customDoubleArray");
        Assert.assertEquals(0.1, value.getJsonNumber(0).doubleValue(), 0.000001);
        Assert.assertEquals(1.1, value.getJsonNumber(1).doubleValue(), 0.000001);
        Assert.assertEquals(2.2, value.getJsonNumber(2).doubleValue(), 0.000001);
        Assert.assertEquals(3.3, value.getJsonNumber(3).doubleValue(), 0.000001);
        Assert.assertEquals(4.4, value.getJsonNumber(4).doubleValue(), 0.000001);
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "validate the name comes from the upn claim")
    public void validateCustomObject() {
        JsonObject value = jwt.getClaim("customObject");
        JsonObject myService = value.getJsonObject("my-service");
        Assert.assertNotNull(myService);
        JsonArray groups = myService.getJsonArray("groups");
        Assert.assertNotNull(groups);
        Assert.assertEquals("group1", groups.getString(0));
        Assert.assertEquals("group2", groups.getString(1));
        JsonArray roles = myService.getJsonArray("roles");
        Assert.assertNotNull(roles);
        Assert.assertEquals("role-in-my-service", roles.getString(0));

        JsonObject serviceB = value.getJsonObject("service-B");
        Assert.assertNotNull(serviceB);
        JsonArray rolesB = serviceB.getJsonArray("roles");
        Assert.assertNotNull(roles);
        Assert.assertEquals("role-in-B", rolesB.getString(0));

        JsonObject serviceC = value.getJsonObject("service-C");
        Assert.assertNotNull(serviceC);
        JsonArray groupsC = serviceC.getJsonArray("groups");
        Assert.assertNotNull(groups);
        Assert.assertEquals("groupC", groupsC.getString(0));
        Assert.assertEquals("web-tier", groupsC.getString(1));
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "validate the name comes from the upn claim")
    public void validateNameIsUPN() {
        Assert.assertEquals("jdoe@example.com", jwt.getName());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "validate the name comes from the upn claim")
    public void validateNameIsPreferredName() throws Exception {
        String token2 = TokenUtils.generateTokenString("/usePreferredName.json");
        JsonWebToken jwt2 = tokenParser.parse(token2, TEST_ISSUER, publicKey);
        Assert.assertEquals("jdoe", jwt2.getName());
    }
    @Test(groups = TEST_GROUP_JWT,
            description = "validate the name comes from the sub claim")
    public void validateNameIsSubject() throws Exception {
        String token2 = TokenUtils.generateTokenString("/useSubject.json");
        JsonWebToken jwt2 = tokenParser.parse(token2, TEST_ISSUER, publicKey);
        Assert.assertEquals("24400320", jwt2.getName());
    }
}
