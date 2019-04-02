/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.CommonsConfigurationAdapter;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.crypto.Aes;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeFactory;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.keystore.directory.DirectoryKeyManager;
import com.intel.kms.keystore.directory.EnvelopeKeyManager;
import com.intel.kms.keystore.directory.setup.EnvelopeKey;
import com.intel.kms.setup.PasswordVault;
import com.intel.kms.api.util.PemKeyEncryptionKeyDescriptor;
import com.intel.kms.api.util.PemUtils;
import com.intel.kms.integrity.setup.NotaryKey;
import com.intel.kms.user.User;
import com.intel.kms.user.jaxrs.UserRepository;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.setup.SetupTask;
import com.intel.mtwilson.setup.console.cmd.Setup;
import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.configuration.ConfigurationException;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
//import com.intel.kms.setup.PasswordVault;

/**
 * User stories:
 * As a client, I am able to register my public key with the server for future key transfers to me
 * As a client, I am able to register an existing key for storage.
 * As a client, I am able to request the server to craete a new key and transfer to me (wrapped in my public key)
 * 
 * @author jbuhacoff
 */
public class InternalRegisterKeyTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(InternalRegisterKeyTest.class);
    private static final ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
    private static final ArrayList<String> keys = new ArrayList<>(); // can be added to or cleared by individual methods as necessary for reusing work
    
    /**
     * Test environment outline:
     * 1. Set system property mtwilson.environment.prefix to random value;
     *    This means all Environment calls will fail to get any values and all
     *    components will use fallback values.
     *    This will avoid collision with developer local environment.
     * 2. Set system property mtwilson.application.id to random value
     *    This allows the application folder to be set inside the target folder.
     * 3. Set system property (testid).home to be inside the target folder.
     * 4. Set system property mtwilson.configuration.file to be test.properties
     * 
     * Folder locations need to be set to target folder
     */
    @BeforeClass
    public static void initializeTestEnvironment() throws IOException, ConfigurationException {
        String testId = RandomUtil.randomHexString(4);
        File testdir = new File("target"+File.separator+"test-data"+File.separator+testId);
        log.debug("Test directory: {}", testdir.getAbsolutePath());
        testdir.mkdirs();
        
        System.setProperty("mtwilson.environment.prefix", "TEST_"+testId+"_");
        System.setProperty("mtwilson.application.id", "test-"+testId);
        System.setProperty("mtwilson.configuration.file", "test.properties");
        System.setProperty("test-"+testId+".home", testdir.getAbsolutePath());
        
        // configuration
        File configurationFile = ConfigurationFactory.getConfigurationFile();
        configurationFile.getParentFile().mkdirs();
        
        log.debug("Test configuration file: {}", configurationFile.getAbsolutePath());
        // create a configuration file with a random master password
        PropertiesConfiguration testconfig = new PropertiesConfiguration();
        testconfig.set("password.vault.key", testId);
        
        try(FileOutputStream out = new FileOutputStream(configurationFile)) {
            testconfig.getProperties().store(out, String.format("test id: %s", testId));
        }
        
        runSetupTasks(testconfig);
        
    }
    
    protected static void runSetupTasks(Configuration configuration) throws IOException, ConfigurationException {
        ArrayList<SetupTask> tasks = new ArrayList<>();
        tasks.add(new PasswordVault());
        tasks.add(new NotaryKey());
        tasks.add(new EnvelopeKey());
        Setup manager = new Setup();
        manager.setOptions(new CommonsConfigurationAdapter(configuration)); // org.apache.commons.configuration.PropertiesConfiguration());
        manager.execute(tasks);
    }
    
    /**
     * Administrator work outline (setup):
     * 1. setup task creates a public key for receiving key registrations
     * 2. administrator grants permission for client to register existing keys
     * 3. administrator provides the kms registration public key to client
     * Client work outline (request):
     * 1. client generates/loads existing key to register
     * 2. client wraps existing key with kms registration public key
     * 3. client sends wrapped key to kms
     * Server work outline (response):
     * 1. Load kms registration public key identified in request
     * 2. Unwrap wrapped key using kms registration public key
     * 3. Validate unwrapped key attributes
     * 4. Wrap key for storage using kms storage key
     * 5. Store key
     * 6. Send register key response object with registered key attributes
     */
    @Test
    public void registerKeyTest() throws IOException, KeyStoreException, CryptographyException {
        ////////////////// setup
        // create kms public key
//        Configuration configuration = ConfigurationFactory.getConfiguration();
//        runSetupTasks(configuration);
        // load kms public key
        DirectoryKeyManager keyManager = new DirectoryKeyManager();
        EnvelopeKeyManager envelopeKeyManager = keyManager.getEnvelopeKeyManager();
        PrivateKeyStore keyStore = envelopeKeyManager.getKeystore();
        List<String> kmsPrivateKeyList = keyStore.aliases();
        assertFalse(kmsPrivateKeyList.isEmpty());
        String kmsKeyId = kmsPrivateKeyList.get(0);
        log.debug("KMS key id: {}", kmsKeyId);
//        PrivateKey kmsPrivateKey = keyStore.getPrivateKey(kmsKeyId);
        Certificate[] kmsCertificates = keyStore.getCertificates(kmsKeyId);
        assertEquals(1, kmsCertificates.length);
        Certificate kmsCertificate = kmsCertificates[0];
        // provide the kms public key to client:
        PublicKey kmsPublicKey = kmsCertificate.getPublicKey();
        ////////////////// client request
        SecretKey key = Aes.generateKey(128);
        log.debug("Secret key length: {} encoded: {}", key.getEncoded().length, Base64.encodeBase64String(key.getEncoded()));
        RsaPublicKeyProtectedPemKeyEnvelopeFactory factory = new RsaPublicKeyProtectedPemKeyEnvelopeFactory(kmsPublicKey, kmsKeyId);
        PemKeyEncryption pem = factory.seal(key);
        log.debug("Wrapped key pem: {}", pem.getDocument().toString());
        RegisterKeyRequest request = new RegisterKeyRequest();
        request.setKey(pem.getDocument().getContent());
        request.setDescriptor(new PemKeyEncryptionKeyDescriptor(pem));
        ////////////////// server action and response
        RegisterKeyResponse response = keyManager.registerKey(request);
        log.debug("Register key response: {}", mapper.writeValueAsString(response));
        KeyCollection keyCollection = new KeyCollection();
        for(KeyAttributes keyAttributes : response.getData()) {
            keys.add(keyAttributes.getKeyId()); // just so we can retrieve it later from another junit test if we're reusing this function as part of another test
            Key keyItem = new Key();
            copy(keyAttributes, keyItem);
            keyCollection.getKeys().add(keyItem);
        }
        log.debug("API register key response: {}", mapper.writeValueAsString(keyCollection));
    }
    
    private void copy(KeyAttributes from, Key to) {
        to.setAlgorithm(from.getAlgorithm());
        to.setDescription(from.getDescription());
        to.setDigestAlgorithm(from.getDigestAlgorithm());
        to.setId(UUID.valueOf(from.getKeyId().toString()));
        to.setKeyLength(from.getKeyLength());
        to.setMode(from.getMode());
        to.setPaddingMode(from.getPaddingMode());
        to.setRole(from.getRole());
        to.setTransferPolicy(from.getTransferPolicy());
        to.setUsername(from.getUsername());
    }
    
    @Test
    public void createKeyTest() throws CryptographyException, IOException {
//        Configuration configuration = ConfigurationFactory.getConfiguration();
//        runSetupTasks(configuration);
        //////////////// client request
        CreateKeyRequest request = new CreateKeyRequest();
        request.setAlgorithm("AES");
        request.setKeyLength(128);
        request.setMode("OFB");
         DirectoryKeyManager keyManager = new DirectoryKeyManager();
       CreateKeyResponse response = keyManager.createKey(request);
        log.debug("Create key response: {}", mapper.writeValueAsString(response));
            keys.add(response.getData().get(0).getKeyId()); // just so we can retrieve it later from another junit test if we're reusing this function as part of another test
       Key keyItem = new Key();
       copy(response.getData().get(0), keyItem);
        log.debug("API create key response: {}", mapper.writeValueAsString(keyItem));
       
    }
    
    @Test
    public void retrieveKeyAttributesTest() throws CryptographyException, IOException {
        // first create a new key... will store its id in the static keys list
        createKeyTest();
         DirectoryKeyManager keyManager = new DirectoryKeyManager();
        GetKeyAttributesRequest request = new GetKeyAttributesRequest();
        request.setKeyId(keys.get(0));
        GetKeyAttributesResponse response = keyManager.getKeyAttributes(request);
        log.debug("Get key attributes response: {}", mapper.writeValueAsString(response));
       Key keyItem = new Key();
       copy(response.getData(), keyItem);
        log.debug("API Get key attributes response: {}", mapper.writeValueAsString(keyItem));
        
    }
    
    /**
     * NOTE: this test shows we allow any authorized user to retrieve a key if
     * the policy allows "authorized user" transfers, regardless of who created/registered
     * the key... KMS does not yet support key ownership or "to-whom" transfer restrictions
     * for non-trust transfers
     * 
     * @throws CryptographyException
     * @throws IOException
     * @throws NoSuchAlgorithmException 
     */
    @Test
    public void transferKeyTest() throws CryptographyException, IOException, NoSuchAlgorithmException {
        createKeyTest();
        // create a user with its own transfer key
        KeyPair userkey = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        User user = new User();
        user.setUsername("testuser");
        user.setTransferKey(userkey.getPublic());
        UserRepository users = new UserRepository();
        users.create(user);
        log.debug("Created user: {}", mapper.writeValueAsString(user)); // should have an id after the create call
        // attempt the transfer
         DirectoryKeyManager keyManager = new DirectoryKeyManager();
         TransferKeyRequest request = new TransferKeyRequest();
        request.setKeyId(keys.get(0));
        request.setUsername(user.getUsername());
        TransferKeyResponse response = keyManager.transferKey(request);
        log.debug("Transfer key response: {}", mapper.writeValueAsString(response));
        Pem pem = PemUtils.fromTransferKeyResponse(response.getKey(), response.getDescriptor());
        log.debug("API transfer key response: {}", pem.toString());
        // now attempt to unwrap the key we received
        RsaPublicKeyProtectedPemKeyEnvelopeOpener opener = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(userkey.getPrivate(), user.getUsername());
        SecretKey received = (SecretKey)opener.unseal(pem);
        log.debug("received secret key: {}", Base64.encodeBase64String(received.getEncoded()));
    }
}
