/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.*;
import com.intel.kms.client.jaxrs2.Keys;
import com.intel.kms.client.jaxrs2.Login;
import com.intel.kms.client.jaxrs2.Login.LoginRequest;
import com.intel.kms.client.jaxrs2.Users;
import com.intel.kms.user.Contact;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class KeyManagerTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyManagerTest.class);
    private static KeyPair wrappingKeypair;
    private static Keys keys;
    private static Users users;
    private static Login login;
    private static ObjectMapper mapper;
    
    @BeforeClass
    public static void setup() throws NoSuchAlgorithmException, Exception {
        
        mapper = new ObjectMapper();
        // create RSA key pair for wrapping keys
        wrappingKeypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        
        client();
    }
    
    public static void client() throws Exception {
        // register tls policy extensions, not needed if you're using the launcher which already loads extensions
        WhiteboardExtensionProvider.register(com.intel.mtwilson.tls.policy.factory.TlsPolicyCreator.class, com.intel.mtwilson.tls.policy.creator.impl.CertificateDigestTlsPolicyCreator.class);
        // configure the kms client
        Properties properties = new Properties();
        properties.setProperty("endpoint.url", "https://127.0.0.1");
        properties.setProperty("tls.policy.certificate.sha256", "751c70c9f2789d3c17f29478eacc158e68436ec6d7808b1f76fb80fe43a45b90");
        properties.setProperty("login.basic.username", "username");
        properties.setProperty("login.basic.password", "password");
        keys = new Keys(properties);
        users = new Users(properties);
        login = new Login(properties);        
    }
    
    public static class PasswordLoginRequest { public String username; public String password; }
    @Test
    public void testLoginForm() throws JsonProcessingException {
        String token = login.getAuthorizationToken(new LoginRequest("username","password"));
        log.debug("testLoginForm token: {}", token);
        login.logout(token);
    }
    
    @Test
    public void testCreateUser() throws JsonProcessingException {
        Contact contact = new Contact();
        contact.setFirstName("FirstName2");
        contact.setLastName("LastName2");
        contact.setEmailAddress("username2@example.com");
        User createUserRequest = new User();
        createUserRequest.setUsername("username3");
        createUserRequest.setContact(contact);
        User createUserResponse = users.createUser(createUserRequest);
        log.debug("create user response: {}", mapper.writeValueAsString(createUserResponse));
    }
    
    /**
     * How to register a key encryption key (KEK) also known as a transfer key.
     * This key is used by the KMS to encrypt keys sent to the client so only
     * the client can see them regardless of the security of the communication
     * channel.
     * 
     * Example code for trust director.
     * 
     */
    @Test
    public void testRegisterPublicKey() throws JsonProcessingException {
        // register public key with kms
        User user = users.findUserByUsername("username");
        user.setTransferKey(wrappingKeypair.getPublic());
        User edited = users.editUser(user);
        // confirmation:
        log.debug("edit user response: {}", mapper.writeValueAsString(edited));
    }
    
    
    /**
     * Example code for a KMS administration application.
     * 
     */
    @Test
    public void testEditPublicKey() throws JsonProcessingException, NoSuchAlgorithmException {
        // find the user, change the public key
        UserFilterCriteria findUserByUsername = new UserFilterCriteria();
        findUserByUsername.usernameEqualTo = "username";
        UserCollection results = users.searchUsers(findUserByUsername);
        if( results.getUsers().isEmpty() ) {
            throw new IllegalStateException("no registered users");
        }
        User user = results.getUsers().get(0);
        log.debug("original user: {}", mapper.writeValueAsString(user));
        KeyPair newkeypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        log.debug("editing transfer key");
        users.editTransferKey(user.getId().toString(), newkeypair.getPublic());
        log.debug("check user again");
        User edited = users.retrieveUser(user.getId().toString());
        log.debug("edited user: {}", mapper.writeValueAsString(edited));
    }
    
    /**
     * Example code for trust director.  Can be wrapped into a utility method.
     * @throws JsonProcessingException
     * @throws CryptographyException 
     */
    @Test
    public void testCreateKey() throws JsonProcessingException, CryptographyException {
        // register new public key with kms
        users.editTransferKey("username", wrappingKeypair.getPublic());
        
        // request kms to create a new key... TODO:  would be nice to be able to say "also send the wrapped key" in the create key request, so we don't need to make a separate transfer request later.
        CreateKeyRequest createKeyRequest = new CreateKeyRequest();
        createKeyRequest.setAlgorithm("AES");
        createKeyRequest.setKeyLength(128);
        createKeyRequest.setMode("OFB");
        Key createKeyResponse = keys.createKey(createKeyRequest);
        log.debug("create key response: {}", mapper.writeValueAsString(createKeyResponse));
        
        /*
        if( createKeyResponse.getData().isEmpty() ) {
            throw new IllegalStateException("Server did not return created key");
        }
        if( createKeyResponse.getData().size() > 1 ) {
            throw new IllegalStateException("Server returned multiple created keys");
        }
        */
        
        // now request the new key content (wrapped) 
        // json:
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest(createKeyResponse.getId().toString());
        TransferKeyResponse transferKeyResponse = keys.transferKey(transferKeyRequest);
        log.debug("transfer key response: {}", mapper.writeValueAsString(transferKeyResponse));
        // pem:
        String transferKeyPemResponse = keys.transferKey(createKeyResponse.getId().toString());
        log.debug("transfer key pem response: {}", transferKeyPemResponse);
        
        // unwrap it using our private key
        RsaPublicKeyProtectedPemKeyEnvelopeOpener opener = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(wrappingKeypair.getPrivate(), "username");
        SecretKey receivedKey = (SecretKey)opener.unseal(Pem.valueOf(transferKeyPemResponse));
        log.debug("Unwrapped key: {}", Base64.encodeBase64String(receivedKey.getEncoded()));
        
    }
    
    // this class could be in the application's project; should use setters/getters
    // also note that after the secret key is used to encrypt the VM  the entire
    // structure should be "thrown away" ... do not store the key anywhere!
    // ... the kms is for storing keys, the app can retrieve it again anytime
    public static class KeyContainer {
        public SecretKey secretKey;
        public URL url;
        public Key attributes;
    }
    
    public KeyContainer requestKeyFromServer() throws CryptographyException {
        // these are the required inputs:
        String username = "username"; // can be instance variable from login properties
        String algorithm = "AES"; // can be method parameter
        Integer length = 128; // can be method parameter
        String mode = "OFB"; // can be method parameter
        // step 1. request server to create a new key        
        CreateKeyRequest createKeyRequest = new CreateKeyRequest();
        createKeyRequest.setAlgorithm(algorithm);
        createKeyRequest.setKeyLength(length);
        createKeyRequest.setMode(mode);
        Key createKeyResponse = keys.createKey(createKeyRequest);
        // step 2. request server to transfer the new key to us (encrypted)
        String transferKeyPemResponse = keys.transferKey(createKeyResponse.getId().toString());
        // step 3. decrypt the requested key
        RsaPublicKeyProtectedPemKeyEnvelopeOpener opener = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(wrappingKeypair.getPrivate(), username);
        SecretKey secretKey = (SecretKey)opener.unseal(Pem.valueOf(transferKeyPemResponse));
        // step 4. package all these into a single container
        KeyContainer keyContainer = new KeyContainer();
        keyContainer.secretKey = secretKey;
        keyContainer.url = createKeyResponse.getTransferLink();
        keyContainer.attributes = createKeyResponse;
        return keyContainer;
    }
    
    
    
    
}
