package com.intel.kms.kmip.client;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil; // from mtwilson-util-crypto dependency
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.keystore.directory.JacksonFileRepository;
import com.intel.kms.kmip.client.exception.KMIPClientException;
import com.intel.kms.kmip.client.util.KMIPApiUtil;
import com.intel.kms.kmip.client.validate.RequestValidator;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.SecretKeyStore;

/**
 * Implementation for a south-bound kmip specific adapter.
 *
 * @author aakash
 *
 */
public class KMIPKeyManager implements KeyManager {

    private static final Logger log = LoggerFactory
            .getLogger(KMIPKeyManager.class);
    Configuration configuration;
    private File keysDirectory;
    private JacksonFileRepository repository;

    // TODO: following constants duplicated from kms-keystore-directory
    // StorageKey setup task; refactor will be required
    public static final String KMS_STORAGE_KEYSTORE_FILE_PROPERTY = "kms.storage.keystore.file";
    public static final String KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY = "kms.storage.keystore.password";

    public static final String ENCODER = "kmip.encoder";
    public static final String DECODER = "kmip.decoder";
    public static final String TRANSPORTLAYER = "kmip.transportLayer";
    public static final String ENDPOINT = "kmip.endpoint";
    public static final String KEYSTORELOCATION = "kmip.keyStoreLocation";
    public static final String KEYSTOREPW = "kmip.keyStorePW";
    // TODO: following constant duplicated from kms-keystore-directory
    // StorageKeyManager; refactor will be required
    public static final String STORAGE_KEYSTORE_TYPE = "JCEKS"; // JCEKS is
    // required in
    // order to
    // store secret
    // keys; JKS
    // only allows
    // private keys

    public static final String STORAGE_KEY = "STORAGE_KEY";
    public static final String KMIP_KEY = "KMIP_KEY";
    public static final String KEY_DESCRIPTOR = "KEY_DESCRIPTOR";

    private SecretKeyStore storageKeyStore = null;

    public KMIPKeyManager() throws IOException, KeyStoreException {
        configuration = ConfigurationFactory.getConfiguration();
        setupKeyStore(configuration);
    }
    
    public KMIPKeyManager(Configuration configuration) throws IOException, KeyStoreException {
        this.configuration = configuration;
        setupKeyStore(configuration);
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

    public void configure(Configuration configuration) throws IOException, KeyStoreException {
        setupKeyStore(configuration);
    }
    
    private void setupKeyStore(Configuration configuration) throws IOException,
            KeyStoreException {
        String keystorePath = configuration.get(
                KMS_STORAGE_KEYSTORE_FILE_PROPERTY, Folders.configuration()
                + File.separator + "storage.jck");
        String keystorePasswordAlias = configuration.get(
                KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "storage_keystore");
        try (PasswordKeyStore passwordVault = PasswordVaultFactory
                .getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                Password keystorePassword = passwordVault
                        .get(keystorePasswordAlias);
                File keystoreFile = new File(keystorePath);
                storageKeyStore = new SecretKeyStore(STORAGE_KEYSTORE_TYPE,
                        keystoreFile, keystorePassword.toCharArray());
            }
        }
        this.configuration = configuration;
        initializeKeysDirectory();
    }

    /**
     * Call out the kmip rest API to create a new secret 1.fetches algorithm and
     * key attributes from create key request 2.Sends request to kmip server
     * which returns uid 3.From uid we retrieve the key generated from KMIP
     * server 4.Double encrypt the key by our own storage key 5.Delete old key
     * from kmi server 6.Register new key to klms server 7.Get uid from response
     * and return in CrateKeyresponse
     *
     * @param request
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest request) {
        CreateKeyResponse response = new CreateKeyResponse();
        List<Fault> faults = new ArrayList<>();
        try {
            // validate the input request
            faults.addAll(RequestValidator.validateCreateKey(request));
            if (!faults.isEmpty()) {
                response.getFaults().addAll(faults);
                return response;
            }

            KMIPClient kmipClient = KMIPClient.getKMIPClient(configuration);
            TransferKeyResponse transferKeyResponse = kmipClient
                    .createSecret(request);
            // Check if the above process was successful
            if (!transferKeyResponse.getFaults().isEmpty()) {
                response.getFaults().addAll(transferKeyResponse.getFaults());
                return response;
            }

            // Encrypt the returned kmip key with the storage key
            RegisterKeyResponse registerKeyResponse = generateKeyFromKMIPKeyAndRegister(
                    transferKeyResponse, request.getAlgorithm(),
                    request.getKeyLength());

            // Check if the above process was successful
            if (!registerKeyResponse.getFaults().isEmpty()) {
                response.getFaults().addAll(registerKeyResponse.getFaults());
                return response;
            }

            // Delete the kmip key
            DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(
                    transferKeyResponse.getDescriptor().getContent().getKeyId());
            DeleteKeyResponse deleteResponse = kmipClient.deleteSecret(deleteKeyRequest);
            if (!deleteResponse.getFaults().isEmpty()) {
                log.error("Failed to delete original key material from kmip");
                response.getFaults().addAll(deleteResponse.getFaults());
            }
            response = KMIPApiUtil
                    .mapRegisterKeyResponseToCreateKeyResponse(registerKeyResponse);
        } catch (KMIPClientException ex) {
            faults.add(new Fault(ex, "Error occurred while create key kmip"));
            response.getFaults().addAll(faults);
            return response;
        }
        return response;
    }

    /**
     * Method to register an already available key into kmip server
     *
     * @param request
     * @return RegisterKeyResponse
     */
    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest request) {
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
            // / CipherKeyAttributes content;
            String algorithm = "AES";
            int keyLength = 128;
            if (request.getDescriptor() != null
                    && request.getDescriptor().getContent() != null) {
                algorithm = request.getDescriptor().getContent().getAlgorithm();
                keyLength = request.getDescriptor().getContent().getKeyLength();
            }
            transferKeyResponse.setDescriptor(request.getDescriptor());
            response = generateKeyFromKMIPKeyAndRegister(transferKeyResponse,
                    algorithm, keyLength);

            // Check if the above process was successful
            if (!response.getFaults().isEmpty()) {
                return response;
            }

        } catch (KMIPClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key by Kmip"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    /**
     * deletes key from kmip server
     *
     * @param DeleteKeyRequest
     * @return DeleteKeyResponse
     */
    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest request) {
        DeleteKeyResponse response = new DeleteKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateDeleteKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        // Get the kmip key id stored in local DB
        CipherKey cipherKey = repository.retrieve(request.getKeyId());
        request = new DeleteKeyRequest(cipherKey.get(KMIP_KEY).toString());

        try {
            response = KMIPClient.getKMIPClient(configuration).deleteSecret(
                    request);
            repository.delete(request.getKeyId());

        } catch (KMIPClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in kmip"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    /**
     * Call out the kmip rest API to transfer/retrieve/get a secret by the
     * secret ID from the meta data
     *
     * @param request
     * @return
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest request) {
        TransferKeyResponse response = new TransferKeyResponse();
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateTransferKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            // Get the kmip key id stored in local DB
            CipherKey cipherKey = repository.retrieve(request.getKeyId());
            request.setKeyId(cipherKey.get(KMIP_KEY).toString());

            // Call kmip to get the secret
            response = KMIPClient.getKMIPClient(configuration).retrieveSecret(
                    request);
            response.setDescriptor((KeyDescriptor) cipherKey
                    .get(KEY_DESCRIPTOR));

            // Unwrap the key using the storage key
            byte[] unwrapKey = unwrapKey(response, cipherKey);
            response.setKey(unwrapKey);
        } catch (KMIPClientException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            faults.add(new Fault(ex,
                    "Error occurred while retrieving key in kmip"));
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
    public SearchKeyAttributesResponse searchKeyAttributes(
            SearchKeyAttributesRequest searchKeyAttributesRequest) {
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        String[] keyIds = keysDirectory.list();
        if (keyIds == null) {
            log.warn("Unable to read keys directory");
        } else {
            for (String keyId : keyIds) {
                CipherKey key = repository.retrieve(keyId);
                KeyAttributes keyAttributes = new KeyAttributes();
                keyAttributes.copyFrom(key);
                keyAttributes.set("encoded", null); // "encoded" is from CipherKey, this avoid leaking the key material
                response.getData().add(keyAttributes);
            }
        }
        return response;
    }

    /**
     * This method generates a new secret from the secret generated by KMIP.
     * then wraps it and stores it back in KMIP
     *
     * @param transferKeyResponse
     * @param createKeyRequest
     * @return RegisterKeyResponse containing the keyId
     */
    private RegisterKeyResponse generateKeyFromKMIPKeyAndRegister(
            TransferKeyResponse transferKeyResponse, String algorithm,
            int keyLength) throws KMIPClientException {
        RegisterKeyResponse registerKeyResponse = new RegisterKeyResponse();
        List<Fault> faults = new ArrayList<>();
        byte[] derivedKey;
        try {
            derivedKey = deriveKeyFromKMIP(transferKeyResponse.getKey(),
                    algorithm, keyLength);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            faults.add(new Fault(ex,
                    "Unable to deriveKeyFromkmip with algorithm " + algorithm
                    + " and key length " + keyLength));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        // Wrap the derived key before storing it back in kmip
        CipherKey storageKey;
        try {
            storageKey = getCurrentStorageKey();
            if (storageKey == null) {
                faults.add(new Fault("Storage key not available"));
                registerKeyResponse.getFaults().addAll(faults);
                return registerKeyResponse;
            }
        } catch (KeyStoreException ex) {
            faults.add(new Fault(ex, "Unable to get the storage key "));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        try {
            transferKeyResponse = wrapKey(derivedKey, storageKey);
            transferKeyResponse.getDescriptor().getEncryption().setKeyLength(keyLength);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException ex) {
            faults.add(new Fault(ex,
                    "Unable to wrap key using the storage key "));
            registerKeyResponse.getFaults().addAll(faults);
            return registerKeyResponse;
        }

        RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
        registerKeyRequest.setKey(transferKeyResponse.getKey());
        registerKeyRequest.setDescriptor(transferKeyResponse.getDescriptor());

        // Call kmip api to register the secret
        registerKeyResponse = KMIPClient.getKMIPClient(configuration)
                .registerSecret(registerKeyRequest);

        // Store the storage key and kmip key which would be used for retrieval
        KeyAttributes ka = registerKeyResponse.getData().get(0);
        CipherKey created = new CipherKey();
        created.copyFrom(storageKey);
        created.setKeyId(new UUID().toString());
        created.set(STORAGE_KEY, storageKey);
        created.set(KMIP_KEY, ka.getKeyId());
        created.set(KEY_DESCRIPTOR, transferKeyResponse.getDescriptor());
        repository.store(created);
        ka.setKeyId(created.getKeyId());

        return registerKeyResponse;
    }

    /**
     * *************************************************************************
     * *************** Utility methods
     * ******************************************
     * **********************************************
     */
    /**
     *
     * @param kmipCreatedKey the raw key material returned from kmip
     * @param algorithm for example "AES"
     * @param keyLengthBits for example 128, 192, or 256 for AES
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] deriveKeyFromKMIP(byte[] kmipCreatedKey, String algorithm,
            int keyLengthBits) throws NoSuchAlgorithmException,
            InvalidKeyException {
        int keyLengthBytes = keyLengthBits / 8;
        HKDF hkdf = new HKDF("SHA256");
        byte[] salt = RandomUtil.randomByteArray(hkdf.getMacLength());// #6304 salt should be hashlen bytes
        byte[] info = String.format("kmip %s-%d", algorithm, keyLengthBytes)
                .getBytes(Charset.forName("UTF-8"));
        byte[] derivedKey = hkdf.deriveKey(salt, kmipCreatedKey,
                keyLengthBytes, info);
        return derivedKey;
    }

    private static String toJavaCipherSpec(CipherKeyAttributes cipherKey) {
        return String.format("%s/%s/%s", cipherKey.getAlgorithm(),
                cipherKey.getMode(), cipherKey.getPaddingMode()); // for example
        // AES/CBC/PKCS5Padding
        // or
        // AES/CBC/NoPadding
    }

    // TODO: maybe refactor to use an "internal" data type instead of
    // TransferKeyResponse, esp. since TransferKeyResponse and
    // RegisterKeyRequest are equivalent, there should be a base class
    private TransferKeyResponse wrapKey(byte[] keyToWrap, CipherKey storageKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(toJavaCipherSpec(storageKey));
        SecretKey secretKey = new SecretKeySpec(storageKey.getEncoded(),
                storageKey.getAlgorithm()); // byte[], "AES"
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(keyToWrap);

        KeyAttributes storageKeyAttributes = new KeyAttributes();
        storageKeyAttributes.copyFrom(storageKey);
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.setEncryption(storageKeyAttributes);
        descriptor.getEncryption().set("iv", Base64.encodeBase64String(iv)); // TODO:
        // "iv"
        // is
        // a
        // typical
        // encryption
        // parameter,
        // possibly
        // need
        // to
        // adjust
        // the
        // KeyDescriptor
        // class
        // to
        // accomodate
        // this
        // in
        // the
        // encryption
        // section
        TransferKeyResponse response = new TransferKeyResponse();
        response.setKey(ciphertext); // wrapped key
        response.setDescriptor(descriptor);
        return response;
    }

    private byte[] unwrapKey(TransferKeyResponse wrappedKey,
            CipherKey storageKey) throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(toJavaCipherSpec(storageKey));
        SecretKey secretKey = new SecretKeySpec(storageKey.getEncoded(),
                storageKey.getAlgorithm()); // byte[], "AES"
        byte[] ciphertext = wrappedKey.getKey();
        byte[] iv = Base64.decodeBase64((String) wrappedKey.getDescriptor()
                .getEncryption().get("iv"));
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
            return null;
        }
        // for now, just get the first available storage key
        List<String> aliases = storageKeyStore.aliases();
        if (aliases.isEmpty()) {
            return null;
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
    private CipherKey getStorageKey(String storageKeyAlias)
            throws KeyStoreException {
        if (storageKeyStore == null) {
            return null;
        }
        SecretKey storageKey = storageKeyStore.get(storageKeyAlias);
        CipherKey key = new CipherKey();
        key.setAlgorithm("AES"); // TODO: current hard-coded storage key
        // algorithm; will require future work
        key.setKeyId(storageKeyAlias);
        key.setKeyLength(storageKey.getEncoded().length * 8); // key length is
        // in bits, so
        // converting
        // from byte[]
        // length
        key.setMode("CBC");
        key.setPaddingMode("NoPadding"); // because storage/wrapping key must be
        // same length or longer than
        // wrapped key; another possible
        // value is PKCS5Padding
        key.setEncoded(storageKey.getEncoded());
        key.set("format", storageKey.getFormat()); // TODO: adjustment required
        // since key encoding format
        // is part of java built-in
        // api, there should be a
        // method for it
        return key;
    }
}
