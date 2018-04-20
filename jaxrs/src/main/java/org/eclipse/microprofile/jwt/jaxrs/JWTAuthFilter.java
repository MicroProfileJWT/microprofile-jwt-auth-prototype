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
package org.eclipse.microprofile.jwt.jaxrs;


import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;

/**
 * A JAX-RS ContainerRequestFilter prototype
 * TODO
 */
@Priority(Priorities.AUTHENTICATION)
@Provider
public class JWTAuthFilter implements ContainerRequestFilter {
	
	private static Logger log = Logger.getLogger(JWTAuthFilter.class.getName());
	
	  // Package accessible to set it in test cases
    @Inject
    JWTAuthContextInfo authContextInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authHeaderVal = requestContext.getHeaderString("Authorization");
        log.fine("JWTAuthFilter.authHeaderVal: "+authHeaderVal);
        if (authHeaderVal != null && authHeaderVal.startsWith("Bearer")) {
            try {
                String bearerToken = authHeaderVal.substring(7);
                JsonWebToken jwtPrincipal = validate(bearerToken);
                // Install the JWT principal as the caller
                final SecurityContext securityContext = requestContext.getSecurityContext();
                JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                requestContext.setSecurityContext(jwtSecurityContext);
                log.fine("Success\n");
            }
            catch (Exception ex) {
            	log.log(Level.WARNING, "Failed setting security context", ex);
                ex.printStackTrace();
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        }
        else {
        	log.info("Failed due to missing Authorization bearer token");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    protected JsonWebToken validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }
}
