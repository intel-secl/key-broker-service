package com.intel.kms.barbican.client;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterAsymmetricKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.BarbicanHttpClient;
import com.intel.kms.barbican.client.validate.RequestValidator;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.barbican.client.util.BarbicanApiUtil;
import com.intel.kms.cipher.EncryptionSecretKeyCipher;
import com.intel.kms.keystore.directory.JacksonFileRepository;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.SecretKeyStore;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 * Implementation for a south-bound Barbican specific adapter.
 *
 * @author Siddharth
 *
 */
public class BarbicanKeyManager implements KeyManager {

    private static final Logger log = LoggerFactory.getLogger(BarbicanKeyManager.class);
    Configuration configuration;
    private File keysDirectory;
    private JacksonFileRepository repository;

    // TODO: following constants duplicated from kms-keystore-directory StorageKey setup task; refactor will be required
    public static final String KMS_STORAGE_KEYSTORE_FILE_PROPERTY = "kms.storage.keystore.file";
    public static final String KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY = "kms.storage.keystore.password";
    // TODO: following constant duplicated from kms-keystore-directory StorageKeyManager; refactor will be required
    public static final String STORAGE_KEYSTORE_TYPE = "JCEKS"; // JCEKS is required in order to store secret keys;  JKS only allows private keys

    public static final String STORAGE_KEY = "STORAGE_KEY";
    public static final String BARBICAN_KEY = "BARBICAN_KEY";
    public static final String KEY_DESCRIPTOR = "KEY_DESCRIPTOR";

    private SecretKeyStore storageKeyStore = null;

    public BarbicanKeyManager() throws IOException, KeyStoreException {
        configuration = ConfigurationFactory.getConfiguration();
        setupKeyStore(configuration);
        initializeKeysDirectory();
    }

    public BarbicanKeyManager(Configuration configuration) throws IOException, KeyStoreException {
        this.configuration = configuration;
        setupKeyStore(configuration);
        initializeKeysDirectory();

    }

    private void initializeKeysDirectory() {
        keysDirectory = new File(Folders.repository("keys"));
        if (!keysDirectory.exists()) {
            if (!keysDirectory.mkdirs()) {
                throw new IllegalStateException("Cannot create keys directory");
            }
        }
        repository = new JacksonFileRepository(keysDirectory);
    }

    private void setupKeyStore(Configuration configuration) throws IOException, KeyStoreException {
        String keystorePath = configuration.get(KMS_STORAGE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "storage.jck");
        String keystorePasswordAlias = configuration.get(KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "storage_keystore");
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                Password keystorePassword = passwordVault.get(keystorePasswordAlias);
                File keystoreFile = new File(keystorePath);
                storageKeyStore = new SecretKeyStore(STORAGE_KEYSTORE_TYPE, keystoreFile, keystorePassword.toCharArray());
            }
        }

    }

    /**
     * Call out the barbican rest API to create a new secret
     *
     * @param request
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest request) {
        log.debug("Inside BarbicanKeyManager createKey ");
        CreateKeyResponse response = new CreateKeyResponse();
        List<Fault> faults = new ArrayList<>();
        try {
            // validate the input request
            faults.addAll(RequestValidator.validateCreateKey(request));
            if (!faults.isEmpty()) {
                response.getFaults().addAll(faults);
                return response;
            }

            BarbicanHttpClient barbicanHttpClient = BarbicanHttpClient.getBarbicanHttpClient(configuration);
            TransferKeyResponse transferKeyResponse = barbicanHttpClient.createSecret(request);

            //Encrypt the returned barbican key with the storage key
            RegisterKeyResponse registerKeyResponse = generateKeyFromBarbicanKeyAndRegister(transferKeyResponse, request.getAlgorithm(), request.getKeyLength());

            //Check if the above process was successful
            if (!registerKeyResponse.getFaults().isEmpty()) {
                response.getFaults().addAll(registerKeyResponse.getFaults());
                return response;
            }

            //Delete the Barbican key
            DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(transferKeyResponse.getDescriptor().getContent().getKeyId());
            DeleteKeyResponse deleteSecret = barbicanHttpClient.deleteSecret(deleteKeyRequest);
            if( !deleteSecret.getFaults().isEmpty() ) {
                log.error("Failed to delete original key material from barbican");
                response.getFaults().addAll(deleteSecret.getFaults());
            }
            response = BarbicanApiUtil.mapRegisterKeyResponseToCreateKeyResponse(registerKeyResponse);
        } catch (BarbicanClientException ex) {
            faults.add(new Fault(ex, "Error occurred while create key in Barbican"));
            response.getFaults().addAll(faults);
            return response;
        }
        return response;
    }

    /**
     * Method to put an already available key into barbican
     *
     * @param request
     * @return RegisterKeyResponse
     */
    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest request) {
        log.debug("Inside BarbicanKeyManager registerKey");
        RegisterKeyResponse response = new RegisterKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateRegisterKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            TransferKeyResponse transferKeyResponse = new TransferKeyResponse();
            transferKeyResponse.setKey(request.getKey());
            CipherKeyAttributes content;
            if (request.getDescriptor() == null) {
                KeyDescriptor descriptor = new KeyDescriptor();
                content = new CipherKeyAttributes();
                content.setAlgorithm("AES");
                content.setKeyLength(128);
                content.setMode("CBC");
                descriptor.setContent(content);
                request.setDescriptor(descriptor);
            } else {
                content = request.getDescriptor().getContent();
            }
            transferKeyResponse.setDescriptor(request.getDescriptor());
            response = generateKeyFromBarbicanKeyAndRegister(transferKeyResponse, content.getAlgorithm(), content.getKeyLength());

            //Check if the above process was successful
            if (!response.getFaults().isEmpty()) {
                return response;
            }

        } catch (BarbicanClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest request) {
        log.debug("Barbican Key Manager delete key request : " + request.getKeyId());
        DeleteKeyResponse response = new DeleteKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateDeleteKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        //Get the Barbican key id stored in local DB
		String repoKeyId = request.getKeyId();
        CipherKeyAttributes cipherKey = repository.retrieve(repoKeyId);
        String barbicanKeyId = cipherKey.get(BARBICAN_KEY).toString();
        log.debug("Key provided by client : " + request.getKeyId() + ". Key to be deleted from Barbican : " + barbicanKeyId);
        request = new DeleteKeyRequest(barbicanKeyId);

        repository.delete(repoKeyId);
        try {
            response = BarbicanHttpClient.getBarbicanHttpClient(configuration).deleteSecret(request);
        } catch (BarbicanClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    /**
     * Call out the barbican rest API to transfer/retrieve/get a secret by the
     * secret ID from the meta data
     *
     * @param request
     * @return
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest request) {
        log.debug("Barbican Key Manager retrienve key request : " + request.getKeyId());
        TransferKeyResponse response = new TransferKeyResponse();
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateTransferKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            //Get the Barbican key id stored in local DB
            CipherKeyAttributes cipherKey = repository.retrieve(request.getKeyId());
            String barbicanKeyId = cipherKey.get(BARBICAN_KEY).toString();
            log.debug("Key provided by client : " + request.getKeyId() + ". Key to be retrieved from Barbican : " + barbicanKeyId);

            request.setKeyId(barbicanKeyId);

            //Call barbican to get the Barbican Key
            response = BarbicanHttpClient.getBarbicanHttpClient(configuration).retrieveSecret(request);
            response.setDescriptor((KeyDescriptor) cipherKey.get(KEY_DESCRIPTOR));
            log.debug("Retrieved stored key digest: {}", Sha384Digest.digestOf(response.getKey()));
            //Unwrap the key using the storage key
            byte[] key = unwrapKey(response, (CipherKey) cipherKey);
            log.debug("Retrieved real key digest: {}", Sha384Digest.digestOf(key));
            response.setKey(key);
        } catch (BarbicanClientException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            faults.add(new Fault(ex, "Error occurred while retrieving key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        GetKeyAttributesResponse keyAttributesResponse = new GetKeyAttributesResponse();
        KeyAttributes attributes = new KeyAttributes();
        attributes.setKeyId(keyAttributesRequest.getKeyId());
        keyAttributesResponse.setData(attributes);
        return keyAttributesResponse;

    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("Barbican key manager searchKeyAttributes");
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        String[] keyIds = keysDirectory.list();
        if( keyIds == null ) {
            log.warn("Unable to read keys directory");
        }
        else {
        for (String keyId : keyIds) {
            CipherKeyAttributes key = repository.retrieve(keyId);
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(key);
            response.getData().add(keyAttributes);
        }
        }
        return response;        
    }

    /**
     * This method generates a new secret from the secret generated by Barbica.
     * then wraps it and stores it back in Barbican
     *
     * @param transferKeyResponse
     * @param algorithm
     * @param keyLength
     * @return RegisterKeyResponse containing the keyId
     */
    private RegisterKeyResponse generateKeyFromBarbicanKeyAndRegister(TransferKeyResponse transferKeyResponse, String algorithm, int keyLength) throws BarbicanClientException {
        RegisterKeyResponse registerKeyResponse = new RegisterKeyResponse();
        List<Fault> faults = new ArrayList<>();
        byte[] derivedKey;
        try {
            derivedKey = deriveKeyFromBarbican(transferKeyResponse.getKey(), algorithm, keyLength);
            
            log.debug("Created real key digest: {}", Sha384Digest.digestOf(derivedKey));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            faults.add(new Fault(ex, "Unable to deriveKeyFromBarbican with algorithm " + algorithm + " and key length " + keyLength));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        //Wrap the derived key before storing it back in barbican
        CipherKey storageKey;
        try {
            storageKey = getCurrentStorageKey();
        } catch (KeyStoreException ex) {
            faults.add(new Fault(ex, "Unable to get the storage key "));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        try {
            transferKeyResponse = wrapKey(derivedKey, storageKey);
            log.debug("Created stored key digest: {}", Sha384Digest.digestOf(transferKeyResponse.getKey()));
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException ex) {
            faults.add(new Fault(ex, "Unable to wrap key using the storage key "));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
        registerKeyRequest.setKey(transferKeyResponse.getKey());
        registerKeyRequest.setDescriptor(transferKeyResponse.getDescriptor());

        //Call barbican api to register the secret
        registerKeyResponse = BarbicanHttpClient.getBarbicanHttpClient(configuration).registerSecret(registerKeyRequest);

        //Store the storage key and barbican key which would be used for retrieval
        KeyAttributes ka = registerKeyResponse.getData().get(0);
        CipherKey created = new CipherKey();
        created.copyFrom(storageKey);
        created.setKeyId(new UUID().toString());
        created.set(STORAGE_KEY, storageKey);
        created.set(BARBICAN_KEY, ka.getKeyId());
        created.set(KEY_DESCRIPTOR, transferKeyResponse.getDescriptor());
        repository.store(created);
        ka.setKeyId(created.getKeyId());

        return registerKeyResponse;
    }

    /**
     * ****************************************************************************************
     * Utility methods
     * ****************************************************************************************
     */
    /**
     *
     * @param barbicanCreatedKey the raw key material returned from Barbican
     * @param algorithm for example "AES"
     * @param keyLengthBits for example 128, 192, or 256 for AES
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] deriveKeyFromBarbican(byte[] barbicanCreatedKey, String algorithm, int keyLengthBits) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey barbicanSecretKey = new SecretKeySpec(barbicanCreatedKey, algorithm);
        if( EncryptionSecretKeyCipher.isPermitted(barbicanSecretKey) ) {
            int keyLengthBytes = keyLengthBits / 8;
            HKDF hkdf = new HKDF("SHA384");
            byte[] salt = RandomUtil.randomByteArray(hkdf.getMacLength()); // #6304 salt should be hashlen bytes
            byte[] info = String.format("Barbican %s-%d", algorithm, keyLengthBits).getBytes(Charset.forName("UTF-8"));
            byte[] derivedKey = hkdf.deriveKey(salt, barbicanCreatedKey, keyLengthBytes, info);
            return derivedKey;
        }
        else {
            throw new IllegalArgumentException("Invalid key");
        }
    }

    private static String toJavaCipherSpec(CipherKeyAttributes cipherKey) {
        return String.format("%s/%s/%s", cipherKey.getAlgorithm(), cipherKey.getMode(), cipherKey.getPaddingMode()); // for example AES/CBC/PKCS5Padding or AES/CBC/NoPadding
    }

    // TODO: maybe refactor to use an "internal" data type instead of TransferKeyResponse, esp. since TransferKeyResponse and RegisterKeyRequest are equivalent, there should be a base class
    private TransferKeyResponse wrapKey(byte[] keyToWrap, CipherKey storageKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(toJavaCipherSpec(storageKey));
        SecretKey secretKey = new SecretKeySpec(storageKey.getEncoded(), storageKey.getAlgorithm()); // byte[], "AES"
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(keyToWrap);

        KeyAttributes storageKeyAttributes = new KeyAttributes();
        storageKeyAttributes.copyFrom(storageKey);
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.setEncryption(storageKeyAttributes);
        descriptor.getEncryption().set("iv", Base64.encodeBase64String(iv)); 
        TransferKeyResponse response = new TransferKeyResponse();
        response.setKey(ciphertext); // wrapped key
        response.setDescriptor(descriptor);
        return response;
    }

    private byte[] unwrapKey(TransferKeyResponse wrappedKey, CipherKey storageKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(toJavaCipherSpec(storageKey));
        SecretKey secretKey = new SecretKeySpec(storageKey.getEncoded(), storageKey.getAlgorithm()); // byte[], "AES"
        byte[] ciphertext = wrappedKey.getKey();
        byte[] iv = Base64.decodeBase64((String) wrappedKey.getDescriptor().getEncryption().get("iv"));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    /**
     * Get the current storage key (to wrap a new key or re-wrap an existing
     * key)
     *
     * @return
     * @throws KeyStoreException
     */
    private CipherKey getCurrentStorageKey() throws KeyStoreException {
        if (storageKeyStore == null) {
            throw new KeyStoreException("storageKeyStore not initialized");
        }
        // for now, just get the first available storage key
        List<String> aliases = storageKeyStore.aliases();
        if (aliases.isEmpty()) {
            throw new KeyStoreException("storageKeyStore is empty");
        }
        String currentStorageKeyAlias = aliases.get(0);
        return getStorageKey(currentStorageKeyAlias);

    }

    /**
     * Get a specific storage key (to unwrap an existing key)
     *
     * @param storageKeyAlias
     * @return
     * @throws KeyStoreException
     */
    private CipherKey getStorageKey(String storageKeyAlias) throws KeyStoreException {
        if (storageKeyStore == null) {
            return null;
        }
        SecretKey storageKey = storageKeyStore.get(storageKeyAlias);
        CipherKey key = new CipherKey();
        key.setAlgorithm("AES"); // TODO: current hard-coded storage key algorithm; will require future work
        key.setKeyId(storageKeyAlias);
        key.setKeyLength(storageKey.getEncoded().length * 8); // key length is in bits, so converting from byte[] length
        key.setMode("CBC");
        key.setPaddingMode("NoPadding"); // because storage/wrapping key must be same length or longer than wrapped key; another possible value is PKCS5Padding
        key.setEncoded(storageKey.getEncoded());
        key.set("format", storageKey.getFormat()); // TODO: adjustment required since key encoding format is part of java built-in api, there should be a method for it
        return key;
    }

    @Override
    public RegisterKeyResponse registerAsymmetricKey(RegisterAsymmetricKeyRequest registerKeyRequest) {
        log.debug("in registerAsymmetricKey");
	RegisterKeyResponse response = new RegisterKeyResponse();
	return response;
    }
}
