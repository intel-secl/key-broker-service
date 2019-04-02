/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.integrity;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.x509.X509Builder;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author jbuhacoff
 */
public class PublicKeyNotary {
    public static String NOTARY_TRANSFER_KEY_CERTIFICATE_VALIDITY_DAYS_PROPERTY = "notary.transfer.key.certificate.validity.days";
    public static String NOTARY_DEFAULT_TRANSFER_KEY_CERTIFICATE_VALIDITY_DAYS = "3650"; // 10 years
    private long transferKeyValidityDays;
    private X509Certificate publicKeyCertificate;
    private PrivateKey privateKey;
    public PublicKeyNotary() throws IOException, KeyStoreException {
        this(ConfigurationFactory.getConfiguration());
    }
    public PublicKeyNotary(Configuration configuration) throws IOException, KeyStoreException {
        try(NotaryKeyManager notaryKeyManager = new NotaryKeyManager(configuration)) {
            String id = notaryKeyManager.getCurrentKeyId();
            if( id != null ) {
                privateKey = notaryKeyManager.getKeystore().getPrivateKey(id);
                publicKeyCertificate = (X509Certificate)notaryKeyManager.getKeystore().getCertificates(id)[0];
            }
        }
        if( privateKey == null || publicKeyCertificate == null ) {
            throw new IllegalStateException("Notary key not found");
        }
        transferKeyValidityDays = Long.valueOf(configuration.get(NOTARY_TRANSFER_KEY_CERTIFICATE_VALIDITY_DAYS_PROPERTY, NOTARY_DEFAULT_TRANSFER_KEY_CERTIFICATE_VALIDITY_DAYS));
    }
    /**
     * Creates an X509 Public Key certificate to bind the given public key
     * and username.
     * The certificate is annotated as a key encryption key only.
     * The username is recorded as the Common Name
     * 
     * @param publicKey
     * @param username
     * @return 
     */
    public X509Certificate certifyTransferKey(PublicKey publicKey, String username) {
        X509Certificate certificate = X509Builder.factory()
                .subjectPublicKey(publicKey)
                .commonName(username)
                .expires(transferKeyValidityDays, TimeUnit.DAYS)
                .issuerName(publicKeyCertificate)
                .issuerPrivateKey(privateKey)
                .keyUsageKeyEncipherment()
                .build();
        return certificate;
    }
}
