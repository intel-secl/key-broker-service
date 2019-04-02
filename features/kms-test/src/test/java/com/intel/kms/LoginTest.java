/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.extensions.Extensions;
import com.intel.kms.client.jaxrs2.Users;
import com.intel.kms.client.jaxrs2.Login;
import com.intel.kms.client.jaxrs2.Login.LoginRequest;
import com.intel.kms.user.User;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyCreator;
import java.util.Properties;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class LoginTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(LoginTest.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    
    @BeforeClass
    public static void init() {
        Extensions.register(TlsPolicyCreator.class, com.intel.mtwilson.tls.policy.creator.impl.CertificateDigestTlsPolicyCreator.class);
    }

    private Properties getEndpointProperties() {
        Properties properties = new Properties();
        properties.setProperty("endpoint.url", "https://10.1.68.32");
        properties.setProperty("tls.policy.certificate.sha256", "751c70c9f2789d3c17f29478eacc158e68436ec6d7808b1f76fb80fe43a45b90");
        properties.setProperty("login.basic.username", "jonathan");
        properties.setProperty("login.basic.password", "jonathan");
        return properties;
    }
    
    @Test
    public void testBasicLoginForToken() throws Exception {
        Login login = new Login(getEndpointProperties());
        String tokenValue = login.getAuthorizationToken();
        log.debug("Got token: {}", tokenValue);
        // try an api call wtih the token
        Properties properties = getEndpointProperties();
        String username = properties.getProperty("login.basic.username");
        properties.remove("login.basic.username");
        properties.remove("login.basic.password");
        properties.setProperty("login.token.value", tokenValue);
        Users users = new Users(properties);
        User user = users.findUserByUsername(username);
        log.debug("Got user: {}", mapper.writeValueAsString(user));
    }
    
    @Test
    public void testUnauthorizedToken() throws Exception {
        Properties properties = getEndpointProperties();
        String username = properties.getProperty("login.basic.username");
        properties.remove("login.basic.username");
        properties.remove("login.basic.password");
        properties.setProperty("login.token.value", "bogus"); // intentionally bogus token, should cause 401 error
        Users users = new Users(properties);
        User user = users.findUserByUsername(username);
        log.debug("Got user: {}", mapper.writeValueAsString(user));
    }
    
}
