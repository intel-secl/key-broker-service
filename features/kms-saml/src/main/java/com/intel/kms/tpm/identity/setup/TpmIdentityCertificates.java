/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.tpm.identity.setup;

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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * @author jbuhacoff
 */
public class TpmIdentityCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmIdentityCertificates.class);
    private final String trustStorePath = Folders.configuration()+"/truststore.";

    public static final String TPM_IDENTITY_CERTIFICATES_FILE_PROPERTY = "mtwilson.tpm.identity.certificates.file";
    public static final String TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY = "mtwilson.tpm.identity.keystore.type";
    public static final String TPM_IDENTITY_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "tpm.identity.jks";
    public static final String TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE = "JKS";
    public static final String MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD = "tpm_identity_certificates"; // the alias of the password
    public static final String BEARER_TOKEN = "bearer.token";
    public static final String BEARER_TOKEN_ENV = "BEARER_TOKEN";
    public static final String MTWILSON_API_URL = "mtwilson.api.url";
    private File tpmIdentityCertificatesFile;
    private Password keystorePassword;
    private Configuration config;
    private String keystoreType;
    private String mtwilsonApiUrl;
    private String bearerToken;

    public File getTpmIdentityCertificatesKeystoreFile() {
        String keystorePath = config.get(TPM_IDENTITY_CERTIFICATES_FILE_PROPERTY, TPM_IDENTITY_DEFAULT_KEYSTORE_FILE);
        return new File(keystorePath);
    }

    public Password getTpmIdentityCertificatesKeystorePassword() throws KeyStoreException, IOException {
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(config)) {
            if (passwordVault.contains(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD)) {
                return passwordVault.get(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD);
            } else {
                return null;
            }
        }
    }

    @Override
    protected void configure() throws Exception {
        config = getConfiguration();
        tpmIdentityCertificatesFile = getTpmIdentityCertificatesKeystoreFile();
        mtwilsonApiUrl = config.get(MTWILSON_API_URL);
        bearerToken = System.getenv(BEARER_TOKEN_ENV);

        if (tpmIdentityCertificatesFile.exists()) {
            log.debug("Configure TPM Identity certificates file at: {}", tpmIdentityCertificatesFile.getAbsolutePath());
            keystorePassword = getTpmIdentityCertificatesKeystorePassword();
            if (keystorePassword == null) {
                configuration("Trusted TPM Identity certificates file exists but password is missing");
            }
        } else {
         // if the tpmIdentity certs file doesn't exist, we should have api url and tls cert sha384 to download it
            
            if (mtwilsonApiUrl == null) {
                configuration("Missing Mt Wilson API URL");
            }
            if (bearerToken == null || bearerToken.isEmpty()) {
                configuration("BEARER_TOKEN not set in the environment");
            }
         }

        keystoreType = config.get(TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY, TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE);
    }

    @Override
    protected void validate() throws Exception {

        if (tpmIdentityCertificatesFile.exists()) {
            log.debug("Validate TPM Identity certificates file at: {}", tpmIdentityCertificatesFile.getAbsolutePath());
            // make sure we have a password for the cert keystore
            if (keystorePassword == null) {
                validation("Missing password for TPM Identity certificate authorities file");
            } else {
                // make sure there's at least one trusted certificate in it
                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
                        log.debug("TPM Identity certificate authorities list is empty");
                    }
                }
            }
        } else {
            validation("Trusted TPM Identity certificate authorities file is missing");
        }
    }

    @Override
    protected void execute() throws Exception {

        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            // generate a keystore password
            keystorePassword = new Password(RandomUtil.randomBase64String(16).toCharArray());

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(config)) {
                passwordVault.set(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD, keystorePassword);
            }
        }

        String extension = "p12";
        if (keystoreType.equalsIgnoreCase("JKS")) {
            extension = "jks";
        }

        String trustStoreFileName = trustStorePath + extension;
        File trustStoreFile = new File(trustStoreFileName);

        // download trusted tpmIdentity certificate authorities from mtwilson
        TlsPolicy tlsPolicy = TlsPolicyBuilder.factory().strictWithKeystore(trustStoreFile, "changeit").build();
        Properties mtwilsonProperties = new Properties();
        mtwilsonProperties.setProperty(BEARER_TOKEN, bearerToken);

        TlsConnection tlsConnection = new TlsConnection(new URL(mtwilsonApiUrl), tlsPolicy);
        CaCertificates mtwilson = new CaCertificates(mtwilsonProperties, tlsConnection);
        X509Certificate certificate = mtwilson.retrieveCaCertificate("privacy");
        // store the certificate
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
            store.set(Sha384Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
