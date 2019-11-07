/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.saml.setup;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.TlsPolicyBuilder;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.certificate.client.jaxrs.CaCertificates;
import com.intel.mtwilson.core.common.utils.AASTokenFetcher;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;

import java.net.URL;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author jbuhacoff
 */
public class SamlCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);
    private final String trustStorePath = Folders.configuration()+"/truststore.";

    public static final String SAML_KEYSTORE_FILE_PROPERTY = "mtwilson.saml.certificates.file";
    public static final String SAML_KEYSTORE_TYPE_PROPERTY = "mtwilson.saml.keystore.type";
    public static final String SAML_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "saml.jks";
    public static final String SAML_DEFAULT_KEYSTORE_TYPE = "JKS";
    public static final String MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS = "saml_certificates"; // the alias of the password
    public static final String BEARER_TOKEN = "bearer.token";
    public static final String MTWILSON_API_URL = "mtwilson.api.url";
    public static final String KMS_ADMIN_USERNAME = "kms.admin.username";
    public static final String KMS_ADMIN_PASSWORD = "kms.admin.password";
    public static final String AAS_API_URL = "aas.api.url";
    private File samlCertificatesFile;
    private Password keystorePassword;
    private Configuration config;
    private String keystoreType;
    private String mtwilsonApiUrl;
    private String username;
    private String password;
    private String aasApiUrl;

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
        mtwilsonApiUrl = config.get(MTWILSON_API_URL);
        username = config.get(KMS_ADMIN_USERNAME);
        password = config.get(KMS_ADMIN_PASSWORD);
        aasApiUrl = config.get(AAS_API_URL);

        if (samlCertificatesFile.exists()) {
            log.debug("Configure SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            keystorePassword = getSamlCertificatesKeystorePassword();
            if( keystorePassword == null ) {
                configuration("Trusted SAML certificates file exists but password is missing");
            }
        } else {
         // if the saml certs file doesn't exist, we should have api url and admin credentials to download it

            if (mtwilsonApiUrl == null) {
                configuration("Missing Mt Wilson API URL");
            }
            if (username == null) {
                configuration("Missing KMS admin username");
            }
            if (password == null) {
                configuration("Missing KMS admin password");
            }
            if (aasApiUrl == null) {
                configuration("Missing AAS api url");
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

        String extension = "p12";
        if (keystoreType.equalsIgnoreCase("JKS")) {
            extension = "jks";
        }

        String trustStoreFileName = trustStorePath + extension;
        File trustStoreFile = new File(trustStoreFileName);

        // download trusted saml certificate authorities from mtwilson
        TlsPolicy tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(trustStoreFile, "changeit").build();
        TlsConnection tlsConnection = new TlsConnection(new URL(aasApiUrl), tlsPolicy);
        Properties mtwilsonProperties = new Properties();
        mtwilsonProperties.setProperty(BEARER_TOKEN, new AASTokenFetcher().getAASToken(username, password, tlsConnection));

        tlsConnection = new TlsConnection(new URL(mtwilsonApiUrl), tlsPolicy);
        CaCertificates mtwilson = new CaCertificates(mtwilsonProperties, tlsConnection);
        X509Certificate certificate = mtwilson.retrieveCaCertificate("saml");
        // store the certificate
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
            store.set(Sha384Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
