/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.directory;

import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.cipher.TransferPublicKeyCipher;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author jbuhacoff
 */
public class EnvelopeKeyManager implements Closeable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(EnvelopeKeyManager.class);
    // constants
    public static final String ENVELOPE_KEYSTORE_FILE_PROPERTY = "envelope.keystore.file";
    public static final String ENVELOPE_KEYSTORE_TYPE_PROPERTY = "envelope.keystore.type";
    public static final String ENVELOPE_KEYSTORE_PASSWORD_PROPERTY = "envelope.keystore.password";
    
    public static final String ENVELOPE_DEFAULT_KEYSTORE_TYPE = "PKCS12"; // JKS and PKCS12 support storing private keys
    private final PrivateKeyStore keystore;

    public EnvelopeKeyManager(String keystoreType, File keystoreFile, char[] keystorePassword) throws KeyStoreException, IOException {
        this.keystore = new PrivateKeyStore(keystoreType, keystoreFile, keystorePassword);
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
     *
     * @return default set of attributes for creating new storage keys
     */
    private KeyAttributes getDefaultKeyAttributes() {
        KeyAttributes keyAttributes = new KeyAttributes();
        keyAttributes.setAlgorithm("RSA");
        keyAttributes.setMode("ECB");
        keyAttributes.setDigestAlgorithm("SHA-384");
//        keyAttributes.id;
        keyAttributes.setKeyLength(3072);
//        keyAttributes.name;
        keyAttributes.setPaddingMode("OAEPWithSHA-384AndMGF1Padding");
        keyAttributes.setRole("keyEncryption");
//        keyAttributes.transferPolicy;  // no transfer policy because this key is not transferable;  maybe this should be a urn with "private" at the end.
        return keyAttributes;
    }

    public KeyAttributes createEnvelopeKey(PrivateKey privateKey, X509Certificate publicKeyCertificate) throws KeyStoreException {
        try {
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(getDefaultKeyAttributes());
            keyAttributes.setKeyId(new UUID().toString());

            // just in case the keystore already has an entry with this id:
            while (keystore.contains(keyAttributes.getKeyId())) {
                log.warn("Duplicate UUID detected: {}", keyAttributes.getKeyId());
                keyAttributes.setKeyId(new UUID().toString());
            }
            
            // check public key parameters
            if( !TransferPublicKeyCipher.isPermitted(publicKeyCertificate.getPublicKey()) ) {
                throw new IllegalArgumentException("Invalid envelope key algorithm or key length");
            }
            
            // check that private key and public key are related
            if( !TransferPublicKeyCipher.isRelated(privateKey, publicKeyCertificate.getPublicKey())) {
                throw new IllegalArgumentException("Unrelated private and public key pair");
            }
            
            if( privateKey.getAlgorithm() != null && !privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                log.warn("Unsupported private key algorithm {}", privateKey.getAlgorithm());
                keyAttributes.setAlgorithm(privateKey.getAlgorithm());
            }
            
            log.debug("Private key algorithm {} format {} encoded length: {}", privateKey.getAlgorithm(), privateKey.getFormat(), privateKey.getEncoded().length);


            keystore.set(keyAttributes.getKeyId(), privateKey, new X509Certificate[] { publicKeyCertificate });

            return keyAttributes;

        } catch (GeneralSecurityException e) {
            throw new KeyStoreException("Cannot create storage key", e);
        }
    }

    public PrivateKeyStore getKeystore() {
        return keystore;
    }

    
}
