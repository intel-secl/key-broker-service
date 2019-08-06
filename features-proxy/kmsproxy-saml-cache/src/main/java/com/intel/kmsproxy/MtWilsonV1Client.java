/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

//Commenting the class file as we are getting saml report from MtWilsonClientV2Client and this class also has dependecny on mtwilso-api
// which we are not building in mtwilson-integration
//package com.intel.kmsproxy;

//import com.intel.dcsg.cpg.configuration.Configuration;
//import com.intel.dcsg.cpg.crypto.CryptographyException;
//import com.intel.dcsg.cpg.crypto.key.password.Password;
//import com.intel.dcsg.cpg.io.FileResource;
//import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
//import com.intel.mtwilson.ApiClient;
//import com.intel.mtwilson.KeystoreUtil;
//import com.intel.mtwilson.api.ApiException;
//import com.intel.mtwilson.api.ClientException;
//import com.intel.mtwilson.configuration.ConfigurationFactory;
//import com.intel.mtwilson.jaxrs2.client.PropertiesTlsPolicyFactory;
//import java.io.File;
//import java.io.IOException;
//import java.net.URL;
//import java.security.GeneralSecurityException;
//import java.util.Properties;

/**
 *
 * @author jbuhacoff
 */
//public class MtWilsonV1Client implements SecurityAssertionProvider {

//    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonV1Client.class);

//    @Override
//    public String getAssertionForSubject(String subject) throws IOException {
//        try {
//            ApiClient mtwilson = getMtWilsonClient();
//            String saml = mtwilson.getSamlForHostByAik(new com.intel.mtwilson.model.Sha256Digest(subject), true); // throws ApiException, SignatureException ; true means we want to force a fresh attestation; set to false if it's ok to get a cached rseponse
//            return saml;
//        } catch (ClientException | GeneralSecurityException | ApiException | CryptographyException e) {
//            throw new IOException(e);
//        }
//    }

//    private ApiClient getMtWilsonClient() throws IOException, ClientException, GeneralSecurityException, CryptographyException {
//        Configuration configuration = ConfigurationFactory.getConfiguration();
//        MtWilsonClientConfiguration clientConfig = new MtWilsonClientConfiguration(configuration);
//        File mtwilsonKeystore = clientConfig.getKeystoreFile();
//        String mtwilsonUsername = clientConfig.getEndpointUsername();
//        log.debug("MtWilson Username: {}", mtwilsonUsername);
//        Password mtwilsonPassword = clientConfig.getKeystorePassword();
//        if( mtwilsonPassword == null ) {
//            log.warn("MtWilson Password is not set");
//            mtwilsonPassword = new Password();
//        }
//        URL mtwilsonUrl = clientConfig.getEndpointURL();
//        if( mtwilsonUrl == null ) {
//            log.warn("MtWilson URL is not set");
//            throw new IllegalArgumentException("Mt Wilson URL is required");
//        }
//        log.debug("MtWilson URL: {}", mtwilsonUrl);
//        String mtwilsonTlsCertSha256 = configuration.get(MtWilsonClientConfiguration.MTWILSON_TLS_CERT_SHA256);
//        /**
//         * We use the v1 API for SAML report so we need to append "/v1" to the
//         * URL
//         */
//        URL v1 = new URL(String.format("%s/v1", mtwilsonUrl.toExternalForm()));

//        Properties p = new Properties();
//        p.setProperty("mtwilson.api.tls.policy.certificate.sha256", mtwilsonTlsCertSha256);
//        TlsPolicy tlsPolicy = PropertiesTlsPolicyFactory.createTlsPolicy(p);

//        ApiClient api = KeystoreUtil.clientForUserInResource(new FileResource(mtwilsonKeystore), mtwilsonUsername, new String(mtwilsonPassword.toCharArray()), v1, tlsPolicy); // throws ClientException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateEncodingException, FileNotFoundException, KeyManagementException
//        return api;
//    }
//}
