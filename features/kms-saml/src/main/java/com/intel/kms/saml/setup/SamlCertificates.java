/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
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
public class SamlCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);
    public static final String SAML_KEYSTORE_FILE_PROPERTY = "mtwilson.saml.certificates.file";
    public static final String SAML_KEYSTORE_TYPE_PROPERTY = "mtwilson.saml.keystore.type";
    public static final String SAML_DEFAULT_KEYSTORE_FILE = Folders.configuration() + File.separator + "saml.jks";
    public static final String SAML_DEFAULT_KEYSTORE_TYPE = "JKS";
    public static final String MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS = "saml_certificates"; // the alias of the password
    public static final String MTWILSON_API_URL = "mtwilson.api.url";
    public static final String MTWILSON_API_USERNAME = "mtwilson.api.username";
    public static final String MTWILSON_API_PASSWORD = "mtwilson.api.password";
    public static final String MTWILSON_TLS_CERT_SHA256 = "mtwilson.tls.cert.sha256";
    private File samlCertificatesFile;
    private Password keystorePassword;
    private String mtwilsonApiUrl;
    private String mtwilsonApiUsername;
    private String mtwilsonApiPassword;
    private String mtwilsonTlsCertSha256;

    public File getSamlCertificatesKeystoreFile() {
        String keystorePath = getConfiguration().get(SAML_KEYSTORE_FILE_PROPERTY, SAML_DEFAULT_KEYSTORE_FILE);
        return new File(keystorePath);
    }

    public Password getSamlCertificatesKeystorePassword() throws KeyStoreException, IOException {
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
            if (passwordVault.contains(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS)) {
                return passwordVault.get(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS);
            } else {
                return null;
            }
        }
    }
    
    @Override
    protected void configure() throws Exception {
        samlCertificatesFile = getSamlCertificatesKeystoreFile();
        mtwilsonApiUrl = getConfiguration().get(MTWILSON_API_URL);
        mtwilsonApiUsername = getConfiguration().get(MTWILSON_API_USERNAME);
        mtwilsonApiPassword = getConfiguration().get(MTWILSON_API_PASSWORD);
        mtwilsonTlsCertSha256 = getConfiguration().get(MTWILSON_TLS_CERT_SHA256);
        if (samlCertificatesFile.exists()) {
            log.debug("Configure SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            keystorePassword = getSamlCertificatesKeystorePassword();
            if( keystorePassword == null ) {
                    configuration("Trusted SAML certificates file exists but password is missing");
            }
        }
        
         else {
         // if the saml certs file doesn't exist, we should have api url and tls cert sha1 to download it
            
         if (mtwilsonApiUrl == null) {
         configuration("Missing Mt Wilson API URL");
         }
         if (mtwilsonApiUsername == null) {
         configuration("Missing Mt Wilson API username");
         }
         if (mtwilsonApiPassword == null) {
         configuration("Missing Mt Wilson API password");
         }
         if (mtwilsonTlsCertSha256 == null) {
         configuration("Missing Mt Wilson TLS certificate SHA-256 fingerprint");
         }
         }
         
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
                String keystoreType = getConfiguration().get(SAML_KEYSTORE_TYPE_PROPERTY, SAML_DEFAULT_KEYSTORE_TYPE);
                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
//                validation("No trusted SAML certificate authorities");// allow it to be empty, user will add cert later
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

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
                passwordVault.set(MTWILSON_SAML_CERTIFICATES_PASSWORD_ALIAS, keystorePassword);
            }

        }

         // download trusted saml certificate authorities from mtwilson
         Properties mtwilsonProperties = new Properties();
         mtwilsonProperties.setProperty("mtwilson.api.url", mtwilsonApiUrl);
         mtwilsonProperties.setProperty("mtwilson.api.username", mtwilsonApiUsername);
         mtwilsonProperties.setProperty("mtwilson.api.password", mtwilsonApiPassword);
         mtwilsonProperties.setProperty("mtwilson.api.tls.policy.certificate.sha256", mtwilsonTlsCertSha256); // for other options see PropertiesTlsPolicyFactory in mtwilson-util-jaxrs2-client
         CaCertificates mtwilson = new CaCertificates(mtwilsonProperties);
//         X509Certificate certificate = mtwilson.getTargetPath("ca-certificates/saml").request(CryptoMediaType.APPLICATION_PKIX_CERT).get(X509Certificate.class);
         X509Certificate certificate = mtwilson.retrieveCaCertificate("saml");
        // store the certificate
        String keystoreType = getConfiguration().get(SAML_KEYSTORE_TYPE_PROPERTY, SAML_DEFAULT_KEYSTORE_TYPE);
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore(keystoreType, new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
            store.set(Sha256Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
