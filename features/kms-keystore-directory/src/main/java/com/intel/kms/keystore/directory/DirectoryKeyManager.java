/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.directory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configurable;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.file.KeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.KeyLogMarkers;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.KeyTransferPolicy;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.KeyNotFound;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.kms.repository.Repository;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author jbuhacoff
 */
public class DirectoryKeyManager implements KeyManager, Configurable {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DirectoryKeyManager.class);
    private Configuration configuration; // non-final to accomodate configure() method
    final private ObjectMapper mapper;
    final protected Repository repository;

    public DirectoryKeyManager() throws IOException {
        this(getUserKeyRepository());
    }
    
    public DirectoryKeyManager(Repository repository) throws IOException {
        this.configuration = ConfigurationFactory.getConfiguration();
        this.mapper = JacksonObjectMapperProvider.createDefaultMapper();
        this.repository = repository;
    }
    
    private static Repository getUserKeyRepository() throws FileNotFoundException {
        File keysDirectory = new File(Folders.repository("keys"));
        if (!keysDirectory.exists()) {
            if (!keysDirectory.mkdirs()) {
                log.error("Cannot create keys directory");
            }
        }
        return new JacksonFileRepository(keysDirectory);
    }

    public EnvelopeKeyManager getEnvelopeKeyManager() throws KeyStoreException, IOException {
        String keystorePath = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "envelope.p12");
        String keystoreType = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_TYPE_PROPERTY, EnvelopeKeyManager.ENVELOPE_DEFAULT_KEYSTORE_TYPE);
        String keystorePasswordAlias = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_PASSWORD_PROPERTY, "envelope_keystore");
        Password keystorePassword = null;
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
        }
        File keystoreFile = new File(keystorePath);
        if (keystoreFile.exists() && keystorePassword != null) {
            return new EnvelopeKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray());
        }
        throw new IllegalStateException("Envelope Key Manager not ready");
    }

    private SecretKey generateKey(String algorithm, int keyLengthBits) throws NoSuchAlgorithmException {
//        try {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm); // "AES"  // throws NoSuchAlgorithmException
        kgen.init(keyLengthBits);
        SecretKey skey = kgen.generateKey();
        return skey;
//        }
//        catch(NoSuchAlgorithmException e) {
//            throw new CryptographyException(e);
//        }
    }

    private Object createDerivationObject(String transferLink) {

        Map<String, Map<String, Object>> map = new HashMap<>();

        Map<String, Object> sub ;
        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "XTS");
        sub.put("key_length", 512);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=dm-crypt");
        map.put("dm-crypt", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=ecryptfs");
        map.put("ecryptfs", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=openssl");
        map.put("openssl", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "HMAC");
//        sub.put("mode","OFB");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-256");
        sub.put("href", transferLink + "?context=hmac");
        map.put("hmac", sub);

        return map;
    }

    /**
     * Currently supports creating only AES keys
     *
     * @param createKeyRequest
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        log.debug("createKey");
        // validate the input
//        SecretKeyReport report = new SecretKeyReport(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());
//        if( !report.isPermitted() ) {
//            CreateKeyResponse response = new CreateKeyResponse();
//            response.getFaults().addAll(report.getFaults());
//            return response;
//        }

        SecretKey skey;
        CipherKey cipherKey = new CipherKey();

//        Protection protection = ProtectionBuilder.factory().algorithm(createKeyRequest.algorithm).keyLengthBits(createKeyRequest.keyLength).mode("OFB8").build();
        ArrayList<Fault> faults = new ArrayList<>();
        try {
            log.debug("createKeyRequest input: {}", mapper.writeValueAsString(createKeyRequest));
            // prepare a response with all the input attributes,
            // a new key id, and the default transfer policy
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
            /*  MOVED TO REMOTEKEYMANAGER */
 /*
            created.setKeyId(new UUID().toString());
            created.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
            created.setTransferLink(getTransferLinkForKeyId(created.getKeyId()));
            * */
            // create the key
//            skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());
           if(created.map().containsKey("descriptor_uri")){
                HKDF hkdf = new HKDF("SHA256");
                cipherKey.setAlgorithm("HKDF");
                cipherKey.setKeyLength(128);
                created.setAlgorithm(cipherKey.getAlgorithm());
                created.setKeyLength(cipherKey.getKeyLength());
                cipherKey.set("salt", RandomUtil.randomByteArray(hkdf.getMacLength()));
                cipherKey.set("descriptor_uri", created.get("descriptor_uri"));
                cipherKey.set("derivation", createDerivationObject(created.getTransferLink().toExternalForm()));
                created.set("derivation", cipherKey.get("derivation"));
                skey = generateKey("AES", 128);
            }else{
                  cipherKey.setAlgorithm(created.getAlgorithm());
                  cipherKey.setKeyLength(created.getKeyLength());
                  cipherKey.setMode(created.getMode());
                  skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());
            }
            cipherKey.setKeyId(created.getKeyId());
            cipherKey.setEncoded(skey.getEncoded());
            cipherKey.setPaddingMode(created.getPaddingMode());
            cipherKey.set("transferPolicy", created.getTransferPolicy());
            cipherKey.set("transferLink", created.getTransferLink().toExternalForm());
            cipherKey.set("digest_algorithm", "SHA-256");
            created.set("digest_algorithm", "SHA-256");
           /* cipherKey.set("derivation", createDerivationObject(created.getTransferLink().toExternalForm()));
            created.set("derivation", cipherKey.get("derivation"));*/
            /* user field removed in M8*/
            /*cipherKey.set("user", "null");
            created.set("user", "null");*/
            /*         
            if (cipherKey.map().containsKey("user")){
                cipherKey.set("user", created.get("user"));
            }
            else{
                cipherKey.set("user", "");
                created.set("user", "");
            }*/
            
            
            if (created.map().containsKey("descriptor_uri")) {
                cipherKey.set("descriptor_uri", created.get("descriptor_uri"));
            }
            if (created.map().containsKey("path")) {
                cipherKey.set("path", created.get("path"));
            }
            if (created.map().containsKey("policy_uri")) {
                cipherKey.set("policy_uri", created.get("policy_uri"));
            }
            if (created.map().containsKey("realm")) {
                cipherKey.set("realm", created.get("realm"));
            }
            /*policy_integrity field removed in M8*/
            /*if (created.map().containsKey("policy_integrity")) {
                cipherKey.set("digest_algorithm", "SHA-256");
                created.set("digest_algorithm", "SHA-256");
                cipherKey.set("derivation", createDerivationObject(created.getTransferLink().toExternalForm()));
                created.set("derivation", cipherKey.get("derivation"));
            }*/
            log.debug("cipherKey : {}", mapper.writeValueAsString(cipherKey));
            log.debug("Storing cipher key {}", cipherKey.getKeyId());
            repository.store(cipherKey);
            // TODO: encrypt the key using a storage key then write a PEM
            // file with the info. 
            log.info(KeyLogMarkers.CREATE_KEY, "Created key id: {}", cipherKey.getKeyId());
            created.setKeyId(cipherKey.getKeyId());
            CreateKeyResponse response = new CreateKeyResponse(created);
            return response;
            // wrap it with a storage key
        } catch (Exception e) {
            log.debug("GenerateKey failed", e);
            /*if (skey != null) {
                 THE DESTROY METHOD IS NEW IN JAVA 8 - ENABLE THIS WHEN WE UPGRADE TO JAVA 8 */
 /*
                try {
                    skey.destroy();
                }
                catch(DestroyFailedException e2) {
                    log.error("Failed to destroy secret key", e2);
                }
                 
            }*/
            cipherKey.clear();
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("deleteKey");
        repository.delete(deleteKeyRequest.getKeyId());
        DeleteKeyResponse deleteKeyResponse = new DeleteKeyResponse();
        log.info(KeyLogMarkers.DELETE_KEY, "Deleted key id: {}", deleteKeyRequest.getKeyId());
        return deleteKeyResponse;
    }

    /**
     * NOTE: RETURNS PLAINTEXT KEY - CALLER MUST WRAP IT AS APPROPRIATE FOR THE
     * CURRENT CONTEXT.
     *
     * @param keyRequest
     * @return
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest keyRequest) {
        log.debug("transferKey");
        TransferKeyResponse response = new TransferKeyResponse();

        // load secret key from store
        CipherKey cipherKey = repository.retrieve(keyRequest.getKeyId());
        if (cipherKey == null) {
            response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
            return response;
        }
        try {
            log.debug("transferKey loaded key with attributes: {}", mapper.writeValueAsString(cipherKey.map()));
            // XXX TODO hmm doesn' thave policy: urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization    even though it's shown by "createkey" respons.... probably the API layer is adding it, we need it in the backend !!
        } catch (Exception e) {
            log.error("transferKey loaded key but cannot serialize", e);
        }

        CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
        keyAttributes.copyFrom(cipherKey);
        response.setKey(cipherKey.getEncoded());
        response.setDescriptor(new KeyDescriptor());
        response.getDescriptor().setContent(keyAttributes);
        return response;

    }


//    @Override
    public KeyTransferPolicy getKeyPolicy(String keyId) {
        log.debug("getKeyPolicy");
        // TODO:   look up the policy.  at least the URI should be provided here,
        //         and maybe this API is not neeed at all since URI is in key attriutes.....   
        KeyTransferPolicy keyTransferPolicy = new KeyTransferPolicy();
        keyTransferPolicy.keyId = keyId;
        return keyTransferPolicy;
    }

    public static class PemKeyEncryptionFromRegisterKeyRequest implements PemKeyEncryption {

        private Pem pem;

        public PemKeyEncryptionFromRegisterKeyRequest(RegisterKeyRequest request) {
            pem = new Pem("ENCRYPTED KEY", request.getKey());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_ID_HEADER, request.getDescriptor().getContent().getKeyId());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER, request.getDescriptor().getContent().getKeyLength() == null ? null : request.getDescriptor().getContent().getKeyLength().toString());
            pem.setHeader(KeyEnvelope.CONTENT_ALGORITHM_HEADER, request.getDescriptor().getContent().getAlgorithm());
            pem.setHeader(KeyEnvelope.CONTENT_MODE_HEADER, request.getDescriptor().getContent().getMode());
            pem.setHeader(KeyEnvelope.CONTENT_PADDING_MODE_HEADER, request.getDescriptor().getContent().getPaddingMode());
            pem.setHeader(KeyEnvelope.ENCRYPTION_KEY_ID_HEADER, request.getDescriptor().getEncryption().getKeyId());
            pem.setHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER, request.getDescriptor().getEncryption().getAlgorithm());
            pem.setHeader(KeyEnvelope.ENCRYPTION_MODE_HEADER, request.getDescriptor().getEncryption().getMode());
            pem.setHeader(KeyEnvelope.ENCRYPTION_PADDING_MODE_HEADER, request.getDescriptor().getEncryption().getPaddingMode());
        }

        @Override
        public String getContentKeyId() {
            return pem.getHeader(KeyEnvelope.CONTENT_KEY_ID_HEADER);
        }

        @Override
        public Integer getContentKeyLength() {
            return pem.getHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER) == null ? null : Integer.valueOf(pem.getHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER));
        }

        @Override
        public String getContentAlgorithm() {
            return pem.getHeader(KeyEnvelope.CONTENT_ALGORITHM_HEADER);
        }

        @Override
        public String getContentMode() {
            return pem.getHeader(KeyEnvelope.CONTENT_MODE_HEADER);
        }

        @Override
        public String getContentPaddingMode() {
            return pem.getHeader(KeyEnvelope.CONTENT_PADDING_MODE_HEADER);
        }

        @Override
        public Pem getDocument() {
            return pem;
        }

        @Override
        public boolean isEncrypted() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER) != null;
        }

        @Override
        public String getEncryptionKeyId() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_KEY_ID_HEADER);
        }

        @Override
        public String getEncryptionAlgorithm() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER);
        }

        @Override
        public String getEncryptionMode() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_MODE_HEADER);
        }

        @Override
        public String getEncryptionPaddingMode() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_PADDING_MODE_HEADER);
        }
    }

    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("registerKey");
        try {
            log.debug("registerKeyRequest: {}", mapper.writeValueAsString(registerKeyRequest));
        } catch (Exception e) {
            log.error("Cannot serialize registerKeyRequest", e);
        }

        KeyDescriptor descriptor = registerKeyRequest.getDescriptor();
        CipherKey cipherKey = new CipherKey();
        if (descriptor != null && descriptor.getContent() != null) {
            if(descriptor.getContent().map().containsKey("descriptor_uri")){
                cipherKey.setAlgorithm("HKDF");
	        cipherKey.setKeyLength(128);
                cipherKey.setEncoded(registerKeyRequest.getKey());
//                Object pathObject = descriptor.getContent().get("path");
//                if (pathObject != null && pathObject instanceof String) {
//                    cipherKey.set("path", (String) pathObject);
//                }
//                
//                Object policy_uri = descriptor.getContent().get("policy_uri");
//                if (policy_uri != null && policy_uri instanceof String) {
//                    cipherKey.set("policy_uri", (String) policy_uri);
//                }
//                
//                Object descriptor_uri = descriptor.getContent().get("descriptor_uri");
//                if (descriptor_uri != null && descriptor_uri instanceof String) {
//                    cipherKey.set("descriptor_uri", (String) descriptor_uri);
//                }
                
                for(String key : descriptor.getContent().map().keySet()) {
                    if (!key.equals("salt")) {
                        log.debug("Keplerlake RegisterKey : copying {} = {}", key, descriptor.getContent().map().get(key));
                        cipherKey.set(key, descriptor.getContent().map().get(key));
                    }
                }
                 /*if (descriptor.getContent().map().containsKey("user")){
                    cipherKey.set("user", descriptor.getContent().get("user"));
                    }
                    else{
                    cipherKey.set("user", "");
                    }*/
//                try {
//                    SecretKey skey = generateKey("AES", 128);
//                    cipherKey.setEncoded(skey.getEncoded());
//                } catch (NoSuchAlgorithmException ex) {
//                    log.error("Error while generating secret key.", ex);
//                }

                if (!descriptor.getContent().map().containsKey("derivation")) {
                    cipherKey.set("derivation", createDerivationObject((String) descriptor.getContent().get("transferLink")));
                }
                cipherKey.set("salt", RandomUtil.randomByteArray(128));
            }
            else{
                cipherKey.setAlgorithm(descriptor.getContent().getAlgorithm());
	        cipherKey.setKeyLength(descriptor.getContent().getKeyLength());
	        cipherKey.setMode(descriptor.getContent().getMode());
            }
            cipherKey.setPaddingMode(descriptor.getContent().getPaddingMode());
	    cipherKey.setKeyId(descriptor.getContent().getKeyId());
	    cipherKey.set("transferPolicy", descriptor.getContent().get("transferPolicy"));
            cipherKey.set("transferLink", descriptor.getContent().get("transferLink"));
/*//            cipherKey.setAlgorithm(descriptor.getContent().getAlgorithm());
            cipherKey.setAlgorithm("HKDF");
            cipherKey.setKeyId(descriptor.getContent().getKeyId());
//            cipherKey.setKeyLength(descriptor.getContent().getKeyLength());
            cipherKey.setKeyLength(128);
//            cipherKey.setMode(descriptor.getContent().getMode());
            cipherKey.setPaddingMode(descriptor.getContent().getPaddingMode());
            cipherKey.set("transferPolicy", descriptor.getContent().get("transferPolicy"));
            cipherKey.set("transferLink", descriptor.getContent().get("transferLink"));
            Object pathObject = descriptor.getContent().get("path");
            if (pathObject != null && pathObject instanceof String) {
                cipherKey.set("path", (String) pathObject);
            }
            
            if (descriptor.getContent().map().containsKey("user")){
                cipherKey.set("user", descriptor.getContent().get("user"));
            }
            else{
                cipherKey.set("user", "");
            }
            if(descriptor.getContent().map().containsKey("derivation")){
                cipherKey.set("derivation", descriptor.getContent().get("derivation"));
            } else {
                cipherKey.set("derivation", createDerivationObject((String) descriptor.getContent().get("transferLink")));
            }
            cipherKey.set("salt", RandomUtil.randomByteArray(128));
        }
*/
        }
        if (cipherKey.getKeyId() == null) {
            cipherKey.setKeyId(new UUID().toString());
        }
        try {
            log.debug("cipherKey: {}", mapper.writeValueAsString(cipherKey));
        } catch (Exception e) {
            log.error("Cannot serialize cipherKey", e);
        }

        if (descriptor != null && descriptor.getEncryption() != null) {
            // key is encrypted
            PrivateKey encryptionPrivateKey = null;
            String encryptionPrivateKeyId = null;
            if (descriptor.getEncryption().getKeyId() != null) {
                // client specified one of our encryption public keys - try to load it
                try (EnvelopeKeyManager envelopeKeyManager = getEnvelopeKeyManager()) {
                    if (envelopeKeyManager.getKeystore().contains(descriptor.getEncryption().getKeyId())) {
                        encryptionPrivateKey = envelopeKeyManager.getKeystore().getPrivateKey(descriptor.getEncryption().getKeyId());
                        encryptionPrivateKeyId = descriptor.getEncryption().getKeyId();
                        log.debug("Found recipient private key: {}", encryptionPrivateKeyId);
                    } else if (log.isDebugEnabled()) {
                        log.debug("Specified recipient private key is not available");
                        List<String> aliases = envelopeKeyManager.getKeystore().aliases();
                        log.debug("Envelope key store has {} keys", aliases.size());
                        for (String alias : aliases) {
                            log.debug("Envelope key: {}", alias);
                        }
                    }
                } catch (IOException | KeyStoreException e) {
                    log.error("Cannot register key", e);
                    RegisterKeyResponse response = new RegisterKeyResponse();
                    response.getFaults().add(new Fault("Cannot load encryption key"));
                    return response;
                }
            } else {
                // if the client did not specify an encryption key id, we can try 
                // either the last known encryption public key we sent them (if we
                // save that information) or the most recently created encryption public key
                // (if we have more than one) or the only encryption public key we have
            }

            if (encryptionPrivateKey != null) {
                // we found a matching private key, use it to unwrap the key sent by the client
                try {
                    PemKeyEncryptionFromRegisterKeyRequest pemKeyEncryption = new PemKeyEncryptionFromRegisterKeyRequest(registerKeyRequest);
                    RsaPublicKeyProtectedPemKeyEnvelopeOpener recipient = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(encryptionPrivateKey, encryptionPrivateKeyId);
                    Key key = recipient.unseal(pemKeyEncryption);
                    cipherKey.setEncoded(key.getEncoded());
                    log.debug("Successfully opened the secret key envelope");
                } catch (CryptographyException e) {
                    log.error("Cannot load encryption private key to unwrap", e);
                    RegisterKeyResponse response = new RegisterKeyResponse();
                    response.getFaults().add(new Fault("Cannot load encryption key"));
                    return response;
                }
            } else {
                RegisterKeyResponse response = new RegisterKeyResponse();
                response.getFaults().add(new Fault("Cannot find encryption key"));
                return response;
            }
        }

        log.debug("Checking for existing key with same id");
        // check that key id is not already in use
        CipherKey existingCipherKey = repository.retrieve(cipherKey.getKeyId());
        if (existingCipherKey != null) {
            RegisterKeyResponse response = new RegisterKeyResponse();
            response.getFaults().add(new Fault("Key with specifie id already exists"));
            return response;
        }

        // store the key and its attributes
        // TODO: encrypt the key using a storage key then write a PEM
        // file with the info. 
        repository.store(cipherKey);
        log.debug("Stored secret key");

        KeyAttributes registered = new KeyAttributes();
        registered.copyFrom(cipherKey);

        // clear cipherkey
        cipherKey.clear();

        log.info(KeyLogMarkers.REGISTER_KEY, "Registered key id: {}", cipherKey.getKeyId());
        RegisterKeyResponse response = new RegisterKeyResponse(registered);
        return response;
    }

//    @Override
    public void setKeyPolicy(String keyId, KeyTransferPolicy keyPolicy) {
        log.debug("setKeyPolicy");
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("searchKeyAttributes");
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        File directory = new File(Folders.repository("keys"));
        String[] keyIds = directory.list();
        if (keyIds == null) {
            log.warn("Unable to read keys directory");
        } else {
            for (String keyId : keyIds) {
                try {
                    CipherKey key = repository.retrieve(keyId);
                    log.debug("retrieved key : {}", mapper.writeValueAsString(key));
                    KeyAttributes keyAttributes = new KeyAttributes();
                    keyAttributes.copyFrom(key);
                    response.getData().add(keyAttributes);
                } catch (JsonProcessingException ex) {
                    log.warn("unable to retrieve key from repository.");
                }
            }
        }
        return response;

    }

    @Override
    public void configure(Configuration configuration) {
        log.debug("configure");
        this.configuration = configuration;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        log.debug("getKeyAttributes");
        try {
            CipherKey cipherKey = repository.retrieve(keyAttributesRequest.getKeyId());
            log.debug("getKeyAttributes fetched in DKM : {}", mapper.writeValueAsString(cipherKey));
            if (cipherKey == null) {
                return null;
            }
            KeyAttributes attributes = new KeyAttributes();
            attributes.copyFrom(cipherKey);
            GetKeyAttributesResponse keyAttributesResponse = new GetKeyAttributesResponse();
            keyAttributesResponse.setData(attributes);
            log.debug("Returning GetKeyAttributesResponse : {}", mapper.writeValueAsString(keyAttributesResponse));
            return keyAttributesResponse;
        } catch (JsonProcessingException ex) {
            log.error("Error while fetching key from repository", ex);
        }
        return null;
    }

    /*
    private Configuration getConfiguration() {
        return configuration;
    }
     */

    public Repository getRepository() {
        return repository;
    }
    
}