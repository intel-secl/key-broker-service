/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory.setup;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_FILE_PROPERTY;
import static com.intel.mtwilson.core.PasswordVaultFactory.PASSWORD_VAULT_KEY_PROPERTY;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.SecretKeyStore;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStoreException;
import java.security.spec.InvalidKeySpecException;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class TestStorageKey {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TestStorageKey.class);

    public static final String KMS_STORAGE_KEYSTORE_FILE_PROPERTY = "kms.storage.keystore.file";
    public static final String KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY = "kms.storage.keystore.password";
    // TODO: following constant duplicated from kms-keystore-directory StorageKeyManager; refactor will be required
    public static final String STORAGE_KEYSTORE_TYPE = "JCEKS"; // JCEKS is required in order to store secret keys;  JKS only allows private keys

    @Test
    public void testLoadStorageKey() throws IOException, KeyStoreException, InvalidKeySpecException {
    Configuration configuration = new PropertiesConfiguration(); // = ConfigurationFactory.getConfiguration();
        configuration.set(PASSWORD_VAULT_FILE_PROPERTY, "target"+File.separator+"password-vault.jck");
        configuration.set(PASSWORD_VAULT_KEY_PROPERTY, "password");
        
        File passwordVaultFile = new File(configuration.get(PASSWORD_VAULT_FILE_PROPERTY, Folders.configuration() + File.separator + "password-vault.jck"));
        log.debug("configuration folder: {}", Folders.configuration());
        log.debug("password vault path: {}", passwordVaultFile.getAbsolutePath());
        log.debug("password vault exists? {}", passwordVaultFile.exists());
        
        String keystorePath = configuration.get(KMS_STORAGE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "storage.jck");
        String keystorePasswordAlias = configuration.get(KMS_STORAGE_KEYSTORE_PASSWORD_PROPERTY, "storage_keystore");
        SecretKeyStore storageKeyStore = null;
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            log.debug("password vault is open");
            if (passwordVault.contains(keystorePasswordAlias)) {
                log.debug("password vault contains alias {}", keystorePasswordAlias);
                Password keystorePassword = passwordVault.get(keystorePasswordAlias);
                File keystoreFile = new File(keystorePath);
                storageKeyStore = new SecretKeyStore(STORAGE_KEYSTORE_TYPE, keystoreFile, keystorePassword.toCharArray());
            }
            else {
                log.debug("password vault contains: {}", StringUtils.join(passwordVault.aliases(), ", "));
                if( passwordVault.aliases().isEmpty() ) {
                    // password vault doesn't really exist, we got a "friendly open" ...
                    passwordVault.set(keystorePasswordAlias, new Password(RandomUtil.randomBase64String(8).toCharArray()));
                    log.debug("added password to vault, run test again to check for password");
                }
            }
        }
        assertNotNull(storageKeyStore);
    }
}
