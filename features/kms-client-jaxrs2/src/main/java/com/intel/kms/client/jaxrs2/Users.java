/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.security.PublicKey;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;

/**
 * The API resource is used to create, delete and update user's information.
 * @author jbuhacoff
 */
public class Users extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Users.class);
    
    /**
     * To use password-based HTTP BASIC authorization with the user server, 
     * the client must be initialized with the following properties:
     * endpoint.url, login.basic.username, login.basic.password, and any valid TLS
     * policy. The example below uses the Properties format, a sample URL, and
     * a sample TLS certificate SHA-256 fingerprint:
     *<pre>
     * endpoint.url=https://kms.example.com
     * tls.policy.certificate.sha256=751c70c9f2789d3c17f29478eacc158e68436ec6d7808b1f76fb80fe43a45b90
     * login.basic.username=client-username
     * login.basic.password=client-password
     * </pre>
     */
    public Users(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public Users(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    /**
     * Creates a user.
     * <pre>
     * This method creates a new user. The user object model includes a username, contact information and a PEM formatted transfer key. 
     * </pre>
     * @param user The serialized user java model object represents the content of the request body.<br/>
     * <pre>
     * 
     *              username (required)              Name of the user to be created
     * 
     *              contact (optional)               Contact information for user, including first name, last name and email address
     * 
     *              transferKeyPem (optional)        PEM formatted transfer key
     * </pre>
     * @return The serialized User java model object that was created.
     * @since ISecL 2.0
     * @mtwRequiresPermissions users:create
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:443/v1/users
     * 
     * Input: 
     * {
     *      "username":"kms-user"
     * }
     * 
     * Output:
     * {
     *      "id": "2e409322-b863-4999-a438-7e000a93e8ba",
     *      "username": "kms-user"
     * }
     * </pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     *  // Create the user model and set a username
     *  User user = new User();
     *  user.setUsername("kms-user");
     * 
     *  // Create the client and call the create API
     *  Users client = new Users(properties);
     *  User newUser = client.create(user);
     * </pre></div>
     */
    public User createUser(User user) {
        log.debug("createUser: {}", getTarget().getUri().toString());
        User created = getTarget().path("/v1/users").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(user), User.class);
        return created;
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param user
     * @return 
     * 
     */
    public void deleteUser(User user) {
        deleteUser(user.getId().toString());
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param userId
     * @return 
     * 
     */
    public void deleteUser(String userId) {
        log.debug("deleteUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", userId);
        getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete();
    }
    
    /***
     * Method supported. Description of method to be added in future.
     * @param user
     * @return 
     * 
     */
    public User editUser(User user) {
        log.debug("editUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", user.getId());
        User edited = getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).put(Entity.json(user), User.class);
        return edited;
    }
    
    /**<pre>
     * This API is used to associate a transfer key public certificate with an existing user.
     * </pre>
     * <pre>
     * @param username user the transfer key is to be associated with.
     * @param transferKey certificate in PEM format.
     * </pre>
     * @since ISecL 2.0
     * @mtwContentTypeReturned No Content
     * @mtwMethodType PUT
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://kms.server.com:kms_port/v1/users/e67076e7-dc87-4990-88c4-d4f231465e2e/transfer-key
     * 
     * Input:
     *         -----BEGIN PUBLIC KEY-----
     *         MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJRFlDyeGGEoueAXzuQl
     *         EqmJGSyoO0DRTjlorzXLtMWCYWKBQqkIwLGQJRkVbRNNT2dwteKT2NYCz3KRXJ8M
     *         QA07DPW1tBYHuqiJj43tzWunPJwu65wZBFucEtN1VDsbRcv7V7326+ccULjfHi6X
     *         kyBhEtidlpFiRgeOMHWesFS53FO0Vdjz0yDnI0MgJ0Gxv39HvFA/K/qdLdbEgQAu
     *         LYzPFZAMWJ7K22lJVXoLTtOrvd/RBkfaJKFjDIr85s2tAsAF5nuIfJDrk9JL9U5W
     *         hYIl/4DXLvvMm+XCz5qYH6z0NKSNWr7by0dWOlVIBM3c7QtDWRXzrnzMjHRHYAei
     *         uwIDAQAB
     *         -----END PUBLIC KEY-----
     *  
     * Output:
     *  204 No Content
     * * </pre></div>
     */
    public boolean editTransferKey(String username, PublicKey transferKey) {
        log.debug("editTransferKey: {}", getTarget().getUri().toString());
        UserFilterCriteria searchUsersRequest = new UserFilterCriteria();
        searchUsersRequest.usernameEqualTo = username;
        UserCollection searchResults = searchUsers(searchUsersRequest);
        if( searchResults.getUsers().isEmpty() ) {
            log.debug("Username not found: {}", username);
            return false;
        }
        if( searchResults.getUsers().size() > 1 ) {
            log.debug("Multiple users found: {} x {}", username, searchResults.getUsers().size());
            return false;
        }
        User user = searchResults.getUsers().get(0);        
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", user.getId().toString());
        String transferKeyPem = RsaUtil.encodePemPublicKey(transferKey);
        Response response = getTarget().path("/v1/users/{id}/transfer-key").resolveTemplates(map).request().put(Entity.entity(transferKeyPem, CryptoMediaType.APPLICATION_X_PEM_FILE));
        log.debug("editTransferKey response status code {}", response.getStatus());
        if( response.getStatusInfo().getFamily().toString().equals(Family.SUCCESSFUL.toString())) {
            return true;
        }
        return false;
    }
    
    /**
     * Searches for user records.
     * @param filterCriteria The content models of the user filter criteria java model object can be used as query parameters.
     * <pre>
     * If any query parameter criteria listed below is fulfilled, the user is added to the return output.
     *          id                      User ID
     * 
     *          usernameEqualTo         User name
     * 
     *          firstNameEqualTo        Contact first name
     * 
     *          lastNameEqualTo         Contact last name
     * 
     *          nameContains            User name contains text specified
     * 
     *          emailAddressEqualTo     Contact email address
     * 
     *          emailAddressContains    Contact email address contains text specified
     * </pre>
     * @return <pre>The serialized UserCollection java model object.</pre>
     * @since ISecL 2.0
     * @mtwRequiresPermissions users:search
     * @mtwContentTypeReturned JSON/XML/YAML
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * https://server.com:443/v1/users?usernameEqualTo=kms-user
     * output:
     * {
     *      "users": [{
     *          "id": "fb25429f-5554-4940-90e7-b6866d6b3fc2",
     *          "username": "kms-user"
     *      }]
     * }
     * </pre></div>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre>
     * // Create the user filter criteria model and set the criteria to be searched
     * UserFilterCriteria filterCriteria = new UserFilterCriteria();
     * filterCriteria.usernameEqualTo = "kms-user";
     * 
     * // Create the client and call the search API
     * Users client = new Users(properties);
     * UserCollection users = client.search(filterCriteria));
     * </pre></div>
     */
    public UserCollection searchUsers(UserFilterCriteria filterCriteria) {
        log.debug("searchUsers: {}", getTarget().getUri().toString());
        UserCollection searchUsersResponse = getTargetPathWithQueryParams("/v1/users", filterCriteria).request().accept(MediaType.APPLICATION_JSON).get(UserCollection.class);
        return searchUsersResponse;
    }

     /***
     * Method supported. Description of method to be added in future.
     * @param username
     * @return 
     * 
     **/
    public User findUserByUsername(String username) {
        UserFilterCriteria findUserByUsername = new UserFilterCriteria();
        findUserByUsername.usernameEqualTo = username;
        UserCollection results = searchUsers(findUserByUsername);
        if( results.getUsers().isEmpty() ) {
            return null;
        }
        User user = results.getUsers().get(0);
        return user;
    }
     /***
     * Method supported. Description of method to be added in future.
     * @param userId
     * @return 
     * 
     **/
    public User retrieveUser(String userId) {
        log.debug("retrieveUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", userId);
        User retrieved = getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(User.class);
        return retrieved;
    }
    
    
}
