package org.eclipse.microprofile.jwt.jaxrs;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class JWTAuthFilterTest {

	@Test
	public void testFilterNull() throws IOException {
		JWTAuthFilter jwtAuthFilter = new JWTAuthFilter();
		ContainerRequestContext requestContext = mock(ContainerRequestContext.class);
		jwtAuthFilter.filter(requestContext);
	}

	@Test
	public void testFilterGiven() throws IOException {
		JWTAuthFilter jwtAuthFilter = new JWTAuthFilter();
		jwtAuthFilter.authContextInfo = mock(JWTAuthContextInfo.class);
		ContainerRequestContext requestContext = mock(ContainerRequestContext.class);
		when(requestContext.getHeaderString(eq("Authorization"))).thenReturn("Bearer JWT-ROCKS");
		jwtAuthFilter.filter(requestContext);
		ArgumentCaptor<Response> response = ArgumentCaptor.forClass(Response.class);
		verify(requestContext).abortWith(response.capture());
		assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getValue().getStatus());
	}

}
