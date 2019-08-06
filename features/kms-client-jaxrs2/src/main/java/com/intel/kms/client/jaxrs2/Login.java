/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.configuration.ReadonlyConfiguration;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

/**
 * The API resource is used to handle creation of authentication token. 
 * @author jbuhacoff
 */
public class Login extends JaxrsClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Login.class);
    private ReadonlyConfiguration configuration;
    
    /**
     ** To use password-based HTTP BASIC authorization with the user server, the
     * client must be initialized with the following properties: endpoint.url,
     * login.basic.username, login.basic.password, and any valid TLS policy. The
     * example below uses the Properties format, a sample URL, and a sample TLS
     * certificate SHA-384 fingerprint:
     * <pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha384=3e290080376a2a27f6488a2e10b40902b2194d701625a9b93d6fb25e5f5deb194b452544f8c5c3603894eb56eccb3057
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     *@param properties
     * @throws Exception 
     */
    public Login(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
        this.configuration = new ReadonlyConfiguration(new PropertiesConfiguration(properties));
    }

    public Login(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
        this.configuration = new ReadonlyConfiguration(configuration);
    }

    public static class LoginRequest {

        public String username;
        public String password;

        public LoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    public static class LoginResponse {

        private String authorizationToken;

        public String getAuthorizationToken() {
            return authorizationToken;
        }

        public void setAuthorizationToken(String authorizationToken) {
            this.authorizationToken = authorizationToken;
        }
    }

    public String getAuthorizationToken() {
        LoginRequest loginRequest = new LoginRequest(configuration.get("login.basic.username"), configuration.get("login.basic.password"));
        return getAuthorizationToken(loginRequest);
    }
    /**
     * Creates an authorization token. Use this authentication token instead of the basic auth params for all other rest API’s. 
     * This helps to secure the password, by not exposing it.
     * @param loginRequest The LoginRequest java model object represents the content of the request body.
     * <pre>
     *         username (required) Username of an existing user. 
     * 
     *         password (required) Password associated with user.
     * </pre>
     * @return 
     * <pre> The response string that contains the following:
     *          authorization_token
     *          authorization_date
     *          not_after 
     *          faults
     * </pre>
     * @since ISecL 2.0
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://kms.server.com:443/v1/login
     * 
     * Input:
     * {
     *   "username":"admin",
     *   "password":"password"
     * }
     * 
     * Output:
     * {
     *    "authorization_token": "pRjvTdnvPBJU0cZ6mmD8vDF3VevFkHkIYOwlEv7E/Ao=",
     *    "authorization_date": "2018-12-06T11:30:46-0800",
     *    "not_after": "2018-12-06T12:00:46-0800",
     *    "faults": [],
     * }
     * 
     **/
    public String getAuthorizationToken(LoginRequest loginRequest) {
        log.debug("getAuthorizationToken: {}", getTarget().getUri().toString());
        LoginResponse loginResponse = getTarget().path("/v1/login").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(loginRequest), LoginResponse.class);
        return loginResponse.getAuthorizationToken();
    }
    
    /**
     * Logout of an existing, valid token.
     * <pre>
     * This method will logout an existing valid token by providing the authentication token string.
     * </pre>
     * @param token The authentication token string value<br/>
     * @since ISecL 2.0
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://kms.server.com:kms_port/v1/logout
     * 
     * Headers:
     * Content-Type: application/json
     * 
     * Input:
     * {
     *      "authorization_token": "pRjvTdnvPBJU0cZ6mmD8vDF3VevFkHkIYOwlEv7E/Ao="
     * }
     * 
     * Output:
     * 204 No Content
     * </pre>
     */
    public void logout(String token) {
        LoginResponse logoutRequest = new LoginResponse();
        logoutRequest.setAuthorizationToken(token);
        getTarget().path("/v1/logout").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(logoutRequest));
    }
    
    
}
