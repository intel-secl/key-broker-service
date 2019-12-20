/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.saml.setup;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;

/**
 * @author jbuhacoff
 */
public class SamlCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);

    public static final String SAML_KEYSTORE_FILE_PROPERTY = "mtwilson.saml.certificates.file";
    public static final String SAML_KEYSTORE_TYPE_PROPERTY = "mtwilson.saml.keystore.type";
    public static final String SAML_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "saml.jks";
    public static final String SAML_DEFAULT_KEYSTORE_TYPE = "PKCS12";
    public static final String MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS = "saml_certificates"; // the alias of the password
    private File samlCertificatesFile;
    private Password keystorePassword;
    private Configuration config;
    private String keystoreType;

    public File getSamlCertificatesKeystoreFile() {
        String keystorePath = config.get(SAML_KEYSTORE_FILE_PROPERTY, SAML_DEFAULT_KEYSTORE_FILE);
        return new File(keystorePath);
    }

    public Password getSamlCertificatesKeystorePassword() throws KeyStoreException, IOException {
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(config)) {
            if (passwordVault.contains(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS)) {
                return passwordVault.get(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS);
            } else {
                return null;
            }
        }
    }
    
    @Override
    protected void configure() throws Exception {
        config = getConfiguration();
        samlCertificatesFile = getSamlCertificatesKeystoreFile();
        if (samlCertificatesFile.exists()) {
            log.debug("Configure SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            keystorePassword = getSamlCertificatesKeystorePassword();
            if( keystorePassword == null ) {
                configuration("Trusted SAML certificates file exists but password is missing");
            }
        }
        keystoreType = config.get(SAML_KEYSTORE_TYPE_PROPERTY, SAML_DEFAULT_KEYSTORE_TYPE);
    }

    @Override
    protected void validate() throws Exception {

        if (samlCertificatesFile.exists()) {
            log.debug("Validate SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            // make sure we have a password for the cert keystore
            if (keystorePassword == null) {
                validation("Missing password for SAML certificate authorities file");
            } else {
                // make sure there's at least one trusted certificate in it
                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
                        log.debug("SAML certificate authorities list is empty");
                    }
                }
            }
        } else {
            validation("Trusted SAML certificate authorities file is missing");
        }
    }

    @Override
    protected void execute() throws Exception {

        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            // generate a keystore password
            keystorePassword = new Password(RandomUtil.randomBase64String(16).toCharArray());

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(config)) {
                passwordVault.set(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS, keystorePassword);
            }
        }

        // store the certificate
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
