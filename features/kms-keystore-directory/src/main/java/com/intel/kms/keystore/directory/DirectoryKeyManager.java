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
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.EcUtil;
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
import com.intel.kms.api.RegisterAsymmetricKeyRequest;
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
import com.intel.mtwilson.util.crypto.key2.AsymmetricKey;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.interfaces.RSAPublicKey;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.openssl.PEMReader;
//import org.bouncycastle.openssl.PEMParser;
//import org.bouncycastle.openssl.PEMKeyPair;
//import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import java.util.concurrent.ThreadLocalRandom;
import java.security.Signature;

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
        sub.put("digest_algorithm", "SHA-384");
        sub.put("href", transferLink + "?context=dm-crypt");
        map.put("dm-crypt", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-384");
        sub.put("href", transferLink + "?context=ecryptfs");
        map.put("ecryptfs", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "AES");
        sub.put("mode", "CBC");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-384");
        sub.put("href", transferLink + "?context=openssl");
        map.put("openssl", sub);

        sub = new HashMap<>();
        sub.put("algorithm", "HMAC");
//        sub.put("mode","OFB");
        sub.put("key_length", 256);
        sub.put("digest_algorithm", "SHA-384");
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

        ArrayList<Fault> faults = new ArrayList<>();

        if (!createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            CreateKeyResponse response = createAsymmetricKey(createKeyRequest);
	    response.getFaults().addAll(faults);
	    return response;
        }
        SecretKey skey;
        CipherKey cipherKey = new CipherKey();

        try {
            log.debug("createKeyRequest input: {}", mapper.writeValueAsString(createKeyRequest));
            // prepare a response with all the input attributes,
            // a new key id, and the default transfer policy
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
	    ///This is added for ISECL Usecase. Rest all is covered in setcommonAttributes() API.
	    if (!(created.map().containsKey("descriptor_uri"))) {
            	cipherKey.setMode(created.getMode());
		cipherKey.set("digest_algorithm", "SHA-384");
		created.set("digest_algorithm", "SHA-384");
	    }
	    skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());
	    cipherKey.setEncoded(skey.getEncoded());
	    setcommonAttributes(created, cipherKey);


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
            cipherKey.clear();
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }
    }

    public void setcommonAttributes(KeyAttributes created, CipherKeyAttributes attributes) {
        attributes.setAlgorithm(created.getAlgorithm());
        attributes.setKeyLength(created.getKeyLength());
        attributes.setKeyId(created.getKeyId());
        attributes.setPaddingMode(created.getPaddingMode());
	attributes.set("transferPolicy", created.getTransferPolicy());
	attributes.set("transferLink", created.getTransferLink().toExternalForm());
	
	if (created.map().containsKey("descriptor_uri")) {
	    attributes.set("descriptor_uri", created.get("descriptor_uri"));
	}
	if (created.map().containsKey("path")) {
	    attributes.set("path", created.get("path"));
	}
	if (created.map().containsKey("policy_uri")) {
	    attributes.set("policy_uri", created.get("policy_uri"));
	}
	if (created.map().containsKey("realm")) {
	    attributes.set("realm", created.get("realm"));
	}
	String keyTransferPolicy = created.getUsagePolicyID();
	if ((keyTransferPolicy != null) && (!keyTransferPolicy.isEmpty())) {
	    attributes.set("usage_policy", created.getUsagePolicyID());
	}
	String ckaLabel = created.getCkaLabel();
	if ((ckaLabel != null) && (!ckaLabel.isEmpty())) {
	    attributes.set("cka_label", created.getCkaLabel());
	}
	String createdDate = created.getCreatedDate();
	if ((createdDate != null) && (!createdDate.isEmpty())) {
	    attributes.set("created_at", created.getCreatedDate());
	}
    }
    
    public CreateKeyResponse createAsymmetricKey(CreateKeyRequest createKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
	    AsymmetricKey asymmetricKey = new AsymmetricKey();
        try {
            log.debug("Asymmetric createKeyRequest input: {}", mapper.writeValueAsString(createKeyRequest));
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
	        KeyPair pair;
	    if ((createKeyRequest.getAlgorithm()).equalsIgnoreCase("RSA")) {
	        pair = RsaUtil.generateRsaKeyPair(createKeyRequest.getKeyLength());
		    asymmetricKey.setPrivateKey(pair.getPrivate().getEncoded());
		    asymmetricKey.setPublicKey(pair.getPublic().getEncoded());
        } else {
            pair = EcUtil.generateEcKeyPair(createKeyRequest.getCurveType());
		    asymmetricKey.setPrivateKey(pair.getPrivate().getEncoded());
		    asymmetricKey.setPublicKey(pair.getPublic().getEncoded());
        }
        setcommonAttributes(created, asymmetricKey);

        log.debug("Storing cipher key {}", asymmetricKey.getKeyId());
        repository.store(asymmetricKey);
        log.info(KeyLogMarkers.CREATE_KEY, "Created key id: {}", asymmetricKey.getKeyId());
        created.setKeyId(asymmetricKey.getKeyId());
        created.setPublicKey(asymmetricKey.getPublicKey());
        CreateKeyResponse response = new CreateKeyResponse(created);
        log.debug("response in DirectoyKeyManager: {}", mapper.writeValueAsString(response));
        return response;
        } catch (Exception e) {
            log.debug("Generate Asymmetric Key failed", e);
            asymmetricKey.clear();
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
        CipherKey cipherKey = (CipherKey)repository.retrieve(keyRequest.getKeyId());
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
                
                for(String key : descriptor.getContent().map().keySet()) {
                    if (!key.equals("salt")) {
                        log.debug("Keplerlake RegisterKey : copying {} = {}", key, descriptor.getContent().map().get(key));
                        cipherKey.set(key, descriptor.getContent().map().get(key));
                    }
                }

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
        CipherKeyAttributes existingCipherKey = repository.retrieve(cipherKey.getKeyId());
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

    @Override
    public RegisterKeyResponse registerAsymmetricKey(RegisterAsymmetricKeyRequest registerKeyRequest) {
        log.debug("registerAsymmetricKey");
	    ArrayList<Fault> faults = new ArrayList<>();

        try {
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(registerKeyRequest);
	        AsymmetricKey asymmetricKey = new AsymmetricKey();
            log.debug("registerKeyRequest for asymmetric key: {}", mapper.writeValueAsString(registerKeyRequest));
	        PrivateKey privateKey;
            PublicKey publicKey;
            boolean keyPairMatches;
            if ((registerKeyRequest.getAlgorithm()).equalsIgnoreCase("RSA")) {
                privateKey = RsaUtil.decodePemPrivateKey(registerKeyRequest.getPrivateKey());
                if (privateKey == null) {
                    faults.add(new InvalidParameter("key format"));
		            RegisterKeyResponse response = new RegisterKeyResponse();
		            response.getFaults().addAll(faults);
                    return response;
                }
		       publicKey = RsaUtil.extractPublicKey(privateKey);
		       int keyLength = ((RSAPublicKey)publicKey).getModulus().bitLength();
		       created.setKeyLength(keyLength);

		       ///Validate the key pair.
		       // create a challenge
		       byte[] challenge = new byte[10000];
		       ThreadLocalRandom.current().nextBytes(challenge);
		       // sign using the private key
		       Signature sig = Signature.getInstance("SHA256withRSA");
		       sig.initSign(privateKey);
		       sig.update(challenge);
		       byte[] signature = sig.sign();
		       // verify signature using the public key
		       sig.initVerify(publicKey);
		       sig.update(challenge);
		       keyPairMatches = sig.verify(signature);
		       log.debug("keyPairMatches: {}", keyPairMatches);
               /*PEMParser pemReader = new PEMParser(new StringReader(registerKeyRequest.getPrivateKey()));
               PEMKeyPair keyPair = (PEMKeyPair) pemReader.readObject();
               JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
               KeyPair kp = converter.getKeyPair(keyPair);*/
            } else {
                privateKey = EcUtil.decodePemPrivateKey(registerKeyRequest.getPrivateKey());
                //privateKey = kp.getPrivate();
	            if (privateKey == null) {
		        faults.add(new InvalidParameter("key format"));
		        RegisterKeyResponse response = new RegisterKeyResponse();
		        response.getFaults().addAll(faults);
		        return response;
            }
            publicKey = EcUtil.extractPublicKey(privateKey, registerKeyRequest.getCurveType());
            asymmetricKey.setCurveType(registerKeyRequest.getCurveType());

	        ///Validate the key pair.
    	    // create a challenge
	        byte[] challenge = new byte[10000];
	        ThreadLocalRandom.current().nextBytes(challenge);
	        // sign using the private key
	        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
	        sig.initSign(privateKey);
	        sig.update(challenge);
	        byte[] signature = sig.sign();
	        // verify signature using the public key
	        sig.initVerify(publicKey);
	        sig.update(challenge);
	        keyPairMatches = sig.verify(signature);
	        log.debug("keyPairMatches: {}", keyPairMatches);
            }
            if (!keyPairMatches) {
		        faults.add(new InvalidParameter("key format is wrong."));
		        RegisterKeyResponse response = new RegisterKeyResponse();
		        response.getFaults().addAll(faults);
		        return response;
            }
            asymmetricKey.setPrivateKey(privateKey.getEncoded());
            asymmetricKey.setPublicKey(publicKey.getEncoded());
            setcommonAttributes(created, asymmetricKey);
	        if (asymmetricKey.getKeyId() == null) {
		        asymmetricKey.setKeyId(new UUID().toString());
            }
            log.debug("Storing cipher key {}", asymmetricKey.getKeyId());
            repository.store(asymmetricKey);
            log.info(KeyLogMarkers.CREATE_KEY, "Registerd key id: {}", asymmetricKey.getKeyId());
            created.setKeyId(asymmetricKey.getKeyId());
            created.setPublicKey(asymmetricKey.getPublicKey());
	        RegisterKeyResponse response = new RegisterKeyResponse(created);
	        log.debug("response in DirectoyKeyManager: {}", mapper.writeValueAsString(response));
	        return response;
        } catch (Exception e) {
            log.error("Cannot serialize registerKeyRequest", e);
	    RegisterKeyResponse response = new RegisterKeyResponse();
	    response.getFaults().addAll(faults);
	    return response;
        }
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
                    //CipherKey key = repository.retrieve(keyId);
                    CipherKeyAttributes key = repository.retrieve(keyId);
                    log.debug("retrieved key : {}", mapper.writeValueAsString(key));
                    KeyAttributes keyAttributes = new KeyAttributes();
		    if (key instanceof CipherKey) {
			keyAttributes.copyFrom((CipherKey)key);
		    } else {
			keyAttributes.copyFrom((AsymmetricKey)key);
		    }
                    //keyAttributes.copyFrom(key);
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
            CipherKeyAttributes cipherKey = repository.retrieve(keyAttributesRequest.getKeyId());
	    GetKeyAttributesResponse keyAttributesResponse = new GetKeyAttributesResponse();
            log.debug("getKeyAttributes fetched in DKM : {}", mapper.writeValueAsString(cipherKey));
            if (cipherKey == null) {
		keyAttributesResponse.getFaults().add(new KeyNotFound(keyAttributesRequest.getKeyId()));
		return keyAttributesResponse; 
            }
            KeyAttributes attributes = new KeyAttributes();
            if (cipherKey instanceof CipherKey) {
                attributes.copyFrom((CipherKey)cipherKey);
            } else {
                attributes.copyFrom((AsymmetricKey)cipherKey);
            }
            //attributes.copyFrom(cipherKey); 
            keyAttributesResponse.setData(attributes);
            log.debug("Returning GetKeyAttributesResponse : {}", mapper.writeValueAsString(keyAttributesResponse));
            return keyAttributesResponse;
        } catch (JsonProcessingException ex) {
            log.error("Error while fetching key from repository", ex);
        }
        return null;
    }

    public Repository getRepository() {
        return repository;
    }
    
}
