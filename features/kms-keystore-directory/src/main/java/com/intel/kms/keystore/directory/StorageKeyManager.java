/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.directory;

import com.intel.mtwilson.util.crypto.keystore.SecretKeyStore;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.api.KeyAttributes;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author jbuhacoff
 */
public class StorageKeyManager implements Closeable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StorageKeyManager.class);
    public static final String STORAGE_KEYSTORE_FILE_PROPERTY = "storage.keystore.file";
    public static final String STORAGE_KEYSTORE_TYPE_PROPERTY = "storage.keystore.type";
    public static final String STORAGE_KEYSTORE_PASSWORD_PROPERTY = "storage.keystore.password";
    
    public static final String STORAGE_DEFAULT_KEYSTORE_TYPE = "JCEKS"; // MTWKS or JCEKS is required in order to store secret keys;  JKS only allows private keys
    private final SecretKeyStore keystore;

    public StorageKeyManager(String keystoreType, File keystoreFile, char[] keystorePassword) throws KeyStoreException, IOException {
        this.keystore = new SecretKeyStore(keystoreType, keystoreFile, keystorePassword);
    }

    @Override
    public void close() throws IOException {
        keystore.close();
    }

    public boolean isEmpty() {
        try {
            return keystore.isEmpty();
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Keystore not open", e);
        }
    }

    /**
     * Precondition: keystore file exists (or throws FileNotFoundException)
     *
     * @return
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException if keystore cannot be loaded
     * @throws NoSuchAlgorithmException is keystore cannot be loaded
     * @throws UnrecoverableKeyException if key cannot be loaded from keystore
     * @throws
     */
    public SecretKey loadStorageKey(String alias) throws KeyStoreException {
        if (!keystore.contains(alias)) {
            log.debug("Storage keystore does not contain alias: {}", alias);
            return null;
        }
        try {
            SecretKey key = keystore.get(alias);
            return key;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException("Cannot load key", e);
        }
    }

    /**
     *
     * @return default set of attributes for creating new storage keys
     */
    private KeyAttributes getDefaultKeyAttributes() {
        KeyAttributes keyAttributes = new KeyAttributes();
        keyAttributes.setAlgorithm("AES");
        keyAttributes.setMode("OFB");
        keyAttributes.setDigestAlgorithm("SHA-384");
//        keyAttributes.id;
        keyAttributes.setKeyLength(128);
//        keyAttributes.name;
//        keyAttributes.paddingMode;
        keyAttributes.setRole("keyEncryption");
//        keyAttributes.transferPolicy;  // no transfer policy because this key is not transferable;  maybe this should be a urn with "private" at the end.
        log.debug("getDefaultKeyAttributes algorithm {} length {} cipher mode {} digest algorithm {}", keyAttributes.getAlgorithm(), keyAttributes.getKeyLength(), keyAttributes.getMode(), keyAttributes.getDigestAlgorithm());
        return keyAttributes;
    }

    public KeyAttributes createStorageKey() throws KeyStoreException {
        try {
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(getDefaultKeyAttributes());
            keyAttributes.setKeyId(new UUID().toString());

            // just in case the keystore already has an entry with this id:
            while (keystore.contains(keyAttributes.getKeyId())) {
                log.warn("Duplicate UUID detected: {}", keyAttributes.getKeyId());
                keyAttributes.setKeyId(new UUID().toString());
            }


            log.debug("Creating storage key id {} algorithm {} length {} cipher mode {} digest algorithm {}", keyAttributes.getKeyId(), keyAttributes.getAlgorithm(), keyAttributes.getKeyLength(), keyAttributes.getMode(), keyAttributes.getDigestAlgorithm());
            
            KeyGenerator kgen = KeyGenerator.getInstance(keyAttributes.getAlgorithm()); // "AES"  // throws NoSuchAlgorithmException
            kgen.init(keyAttributes.getKeyLength());
            SecretKey skey = kgen.generateKey();
            
            log.debug("Secret key algorithm {} format {} encoded length: {}", skey.getAlgorithm(), skey.getFormat(), skey.getEncoded().length);
            
            keystore.set(keyAttributes.getKeyId(), skey);

            return keyAttributes;

        } catch (GeneralSecurityException e) {
            throw new KeyStoreException("Cannot create storage key", e);
        }
    }
}
