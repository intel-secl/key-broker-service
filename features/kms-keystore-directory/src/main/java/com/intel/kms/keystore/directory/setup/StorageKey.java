/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.setup.AbstractSetupTask;
import java.io.File;
import java.security.KeyStoreException;
import com.intel.kms.keystore.directory.StorageKeyManager;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.IOException;

/**
 * Creates a private key and self-signed certificate. The "envelope key" is the
 * public key with which clients can encrypt keys they are registering so that
 * only the KMS can read them.
 *
 * A self-signed certificate is also generated so clients can have some
 * information about the KMS they will be contacting. The certificate shares the
 * same subject information as the TLS certificate by default.
 *
 * JKS (.jks) provider can only store private keys (asymmetric) JCEKS (.jcs)
 * provider can store private and secret keys but only supports ASCII passwords
 * PCKS12 (.p12) provider can store only private keys and only supports ASCII
 * passwords
 *
 * @author jbuhacoff
 */
public class StorageKey extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StorageKey.class);
    private String keystorePath;
    private String keystoreType;
    private String keystorePasswordAlias;
    private File keystoreFile;
    private Password keystorePassword;

//    private String storageKeyAlgorithm;
//    private int storageKeyLengthBits;
    @Override
    protected void configure() throws Exception {
        keystorePath = getConfiguration().get(StorageKeyManager.STORAGE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "storage.jck");
        keystoreType = getConfiguration().get(StorageKeyManager.STORAGE_KEYSTORE_TYPE_PROPERTY, StorageKeyManager.STORAGE_DEFAULT_KEYSTORE_TYPE);
        keystorePasswordAlias = getConfiguration().get(StorageKeyManager.STORAGE_KEYSTORE_PASSWORD_PROPERTY, "storage_keystore");

        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
            keystoreFile = new File(keystorePath);

            if (keystoreFile.exists()) {
                // we only need to know the password if the file already exists
                // if user lost password, delete the file and we can recreate it
                // with a new random password
                if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
                    configuration("Storage keystore exists but password is missing");
                }
            }
        }

//        storageKeyAlgorithm = storageKeyManager.getStorageKeyAlgorithm();
//        storageKeyLengthBits = storageKeyManager.getStorageKeyLengthBits();

    }

    @Override
    protected void validate() throws Exception {
        if (!keystoreFile.exists()) {
            validation("Keystore file was not created");
            return;
        }
        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            validation("Keystore password not created");
            return;
        }

        try (StorageKeyManager storageKeyManager = new StorageKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray())) {
            if (storageKeyManager.isEmpty()) {
                validation("Keystore is empty");
            }
        } catch (KeyStoreException | IOException e) {
            validation("Cannot read storage key", e);
        }

    }

    @Override
    protected void execute() throws Exception {
        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            // generate a keystore password
            keystorePassword = new Password(RandomUtil.randomBase64String(16).toCharArray());

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
                passwordVault.set(keystorePasswordAlias, keystorePassword);
            }

        }

        // ensure directories exist
        if (!keystoreFile.getParentFile().exists()) {
            if (keystoreFile.getParentFile().mkdirs()) {
                log.debug("Created directory {}", keystoreFile.getParentFile().getAbsolutePath());
            }
        }

        try (StorageKeyManager storageKeyManager = new StorageKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray())) {
            storageKeyManager.createStorageKey();
        }

        // save the settings in configuration;  DO NOT SAVE MASTER KEY
        getConfiguration().set(StorageKeyManager.STORAGE_KEYSTORE_FILE_PROPERTY, keystorePath);
        getConfiguration().set(StorageKeyManager.STORAGE_KEYSTORE_TYPE_PROPERTY, keystoreType);
        getConfiguration().set(StorageKeyManager.STORAGE_KEYSTORE_PASSWORD_PROPERTY, keystorePasswordAlias);
    }
}
