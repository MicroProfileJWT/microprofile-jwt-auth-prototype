package org.eclipse.microprofile.jwt.test.format;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.impl.DefaultJWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;

public class TCKTokenParser implements ITokenParser {
    @Override
    public JsonWebToken parse(String bearerToken, String issuer, PublicKey signedBy) throws Exception {
        JWTAuthContextInfo authContextInfo = new JWTAuthContextInfo((RSAPublicKey) signedBy, issuer);
        JWTCallerPrincipalFactory factory = DefaultJWTCallerPrincipalFactory.instance();
        return factory.parse(bearerToken, authContextInfo);
    }
}
