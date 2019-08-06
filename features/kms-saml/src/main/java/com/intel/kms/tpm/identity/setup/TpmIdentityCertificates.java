/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.tpm.identity.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.certificate.client.jaxrs.CaCertificates;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Properties;
/**
 * @author jbuhacoff
 */
public class TpmIdentityCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmIdentityCertificates.class);
    public static final String TPM_IDENTITY_CERTIFICATES_FILE_PROPERTY = "mtwilson.tpm.identity.certificates.file";
    public static final String TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY = "mtwilson.tpm.identity.keystore.type";
    public static final String TPM_IDENTITY_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "tpm.identity.jks";
    public static final String TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE = "JKS";
    public static final String MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD = "tpm_identity_certificates"; // the alias of the password
    public static final String MTWILSON_API_URL = "mtwilson.api.url";
    public static final String MTWILSON_API_USERNAME = "mtwilson.api.username";
    public static final String MTWILSON_API_PASSWORD = "mtwilson.api.password";
    public static final String MTWILSON_TLS_CERT_SHA384 = "mtwilson.tls.cert.sha384";
    private File tpmIdentityCertificatesFile;
    private Password keystorePassword;
    private String mtwilsonApiUrl;
    private String mtwilsonApiUsername;
    private String mtwilsonApiPassword;
    private String mtwilsonTlsCertSha384;

    public File getTpmIdentityCertificatesKeystoreFile() {
        String keystorePath = getConfiguration().get(TPM_IDENTITY_CERTIFICATES_FILE_PROPERTY, TPM_IDENTITY_DEFAULT_KEYSTORE_FILE);
        return new File(keystorePath);
    }

    public Password getTpmIdentityCertificatesKeystorePassword() throws KeyStoreException, IOException {
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
            if (passwordVault.contains(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD)) {
                return passwordVault.get(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD);
            } else {
                return null;
            }
        }
    }

    @Override
    protected void configure() throws Exception {
        tpmIdentityCertificatesFile = getTpmIdentityCertificatesKeystoreFile();
        mtwilsonApiUrl = getConfiguration().get(MTWILSON_API_URL);
        mtwilsonApiUsername = getConfiguration().get(MTWILSON_API_USERNAME);
        mtwilsonApiPassword = getConfiguration().get(MTWILSON_API_PASSWORD);
        mtwilsonTlsCertSha384 = getConfiguration().get(MTWILSON_TLS_CERT_SHA384);
        if (tpmIdentityCertificatesFile.exists()) {
            log.debug("Configure TPM Identity certificates file at: {}", tpmIdentityCertificatesFile.getAbsolutePath());
            keystorePassword = getTpmIdentityCertificatesKeystorePassword();
            if (keystorePassword == null) {
                configuration("Trusted TPM Identity certificates file exists but password is missing");
            }
        }
        
         else {
         // if the tpmIdentity certs file doesn't exist, we should have api url and tls cert sha384 to download it
            
         if (mtwilsonApiUrl == null) {
         configuration("Missing Mt Wilson API URL");
         }
         if (mtwilsonApiUsername == null) {
         configuration("Missing Mt Wilson API username");
         }
         if (mtwilsonApiPassword == null) {
         configuration("Missing Mt Wilson API password");
         }
         if (mtwilsonTlsCertSha384 == null) {
         configuration("Missing Mt Wilson TLS certificate SHA-384 fingerprint");
         }
         }
         
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
                String keystoreType = getConfiguration().get(TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY, TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE);
                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
                        //validation("No trusted TPM Identity certificate authorities");  // allow it to be empty, user will add cert later
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

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
                passwordVault.set(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD, keystorePassword);
            }

        }

        
         // download trusted tpmIdentity certificate authorities from mtwilson
         Properties mtwilsonProperties = new Properties();
         mtwilsonProperties.setProperty("mtwilson.api.url", mtwilsonApiUrl);
         mtwilsonProperties.setProperty("mtwilson.api.username", mtwilsonApiUsername);
         mtwilsonProperties.setProperty("mtwilson.api.password", mtwilsonApiPassword);
         mtwilsonProperties.setProperty("mtwilson.api.tls.policy.certificate.sha384", mtwilsonTlsCertSha384); // for other options see PropertiesTlsPolicyFactory in mtwilson-util-jaxrs2-client
         //MtWilsonClient mtwilson = new MtWilsonClient(mtwilsonProperties);
         //X509Certificate certificate = mtwilson.getTargetPath("ca-certificates/tpmIdentity").request(CryptoMediaType.APPLICATION_PKIX_CERT).get(X509Certificate.class);
         CaCertificates mtwilson = new CaCertificates(mtwilsonProperties);
         X509Certificate certificate = mtwilson.retrieveCaCertificate("privacy");
         
        // store the certificate
        String keystoreType = getConfiguration().get(TPM_IDENTITY_KEYSTORE_TYPE_PROPERTY, TPM_IDENTITY_DEFAULT_KEYSTORE_TYPE);
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
            store.set(Sha384Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
