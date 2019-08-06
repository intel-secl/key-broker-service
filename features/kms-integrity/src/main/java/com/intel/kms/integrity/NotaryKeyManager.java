/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.integrity;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.ExistingFileResource;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 *
 * @author jbuhacoff
 */
public class NotaryKeyManager implements Closeable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(NotaryKeyManager.class);
    // constants
    public static final String NOTARY_KEYSTORE_FILE_PROPERTY = "notary.keystore.file";
    public static final String NOTARY_KEYSTORE_TYPE_PROPERTY = "notary.keystore.type";
    public static final String NOTARY_KEYSTORE_PASSWORD_ALIAS_PROPERTY = "notary.keystore.password";
    public static final String NOTARY_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "notary.p12";
    public static final String NOTARY_DEFAULT_KEYSTORE_TYPE = "PKCS12"; // JKS and PKCS12 support storing private keys
    public static final String NOTARY_DEFAULT_KEYSTORE_PASSWORD_ALIAS = "notary"; // the password alias in the vault, not the actual password
    private String keystoreType;
    private String keystorePath;
    private String keystorePasswordAlias;
    private PrivateKeyStore keystore;

    public NotaryKeyManager() throws IOException, KeyStoreException {
        this(ConfigurationFactory.getConfiguration());
    }

    public NotaryKeyManager(Configuration configuration) throws IOException, KeyStoreException {
        keystoreType = configuration.get(NOTARY_KEYSTORE_TYPE_PROPERTY, NOTARY_DEFAULT_KEYSTORE_TYPE);
        keystorePath = configuration.get(NOTARY_KEYSTORE_FILE_PROPERTY, NOTARY_DEFAULT_KEYSTORE_FILE);
        File keystoreFile = new File(keystorePath);
        keystorePasswordAlias = configuration.get(NOTARY_KEYSTORE_PASSWORD_ALIAS_PROPERTY, NOTARY_DEFAULT_KEYSTORE_PASSWORD_ALIAS);
        Password keystorePassword = null;
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                log.debug("Notary found keystore password with alias {}", keystorePasswordAlias);
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
        }
        if( keystorePassword == null ) {
            throw new IllegalStateException(String.format("password vault missing notary keystore password alias: %s",keystorePasswordAlias));
        }
        else {
            log.debug("Notary configured keystore and password");
            this.keystore = new PrivateKeyStore(keystoreType, new FileResource(keystoreFile), keystorePassword);
        }
    }

    public PrivateKeyStore getKeystore() {
        return keystore;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystorePasswordAlias() {
        return keystorePasswordAlias;
    }

    /**
     * Returns the first available key id. In the future this may be
     * improved to consider notBefore and notAfter dates on the corresponding
     * certificate.
     *
     * @return a notary key id, or null if one is not available
     * @throws KeyStoreException
     */
    public String getCurrentKeyId() throws KeyStoreException {
        if (keystore == null) {
            return null;
        }

        // in a database implementation this loop would be replaced by query
        // for most recently added notary public key certificate.
        // 
        for (String alias : keystore.aliases()) {
            log.debug("Notary key: {}", alias);
            Certificate[] certs = keystore.getCertificates(alias);
            if (certs == null || certs.length == 0) {
                continue;
            }
            for (Certificate cert : certs) {
                X509Certificate x509 = (X509Certificate) cert;
                log.debug("Notary cert: {}", x509.getSubjectX500Principal().getName());

            }
            return alias;
        }
        return null;
    }

    @Override
    public void close() throws IOException {
        if (keystore != null) {
            keystore.close();
        }
    }
}
