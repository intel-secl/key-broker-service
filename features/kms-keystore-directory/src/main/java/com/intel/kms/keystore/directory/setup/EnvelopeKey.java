/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.directory.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.net.NetUtils;
import com.intel.dcsg.cpg.x509.X509Builder;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.kms.keystore.directory.EnvelopeKeyManager;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.Folders;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.KeyAttributes;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

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
public class EnvelopeKey extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(EnvelopeKey.class);
    // configuration keys
    private static final String KMS_TLS_CERT_DN = "kms.tls.cert.dn";
    private static final String KMS_TLS_CERT_IP = "kms.tls.cert.ip";
    private static final String KMS_TLS_CERT_DNS = "kms.tls.cert.dns";
    private String keystorePath;
    private String keystoreType;
    private File keystoreFile;
    private String keystorePasswordAlias;
    private Password keystorePassword;
    private String dn;
    private String[] ip;
    private String[] dns;

    @Override
    protected void configure() throws Exception {
        keystorePath = getConfiguration().get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "envelope.p12");
        keystoreType = getConfiguration().get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_TYPE_PROPERTY, EnvelopeKeyManager.ENVELOPE_DEFAULT_KEYSTORE_TYPE);
        keystorePasswordAlias = getConfiguration().get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_PASSWORD_PROPERTY, "envelope_keystore");

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
                    configuration("Envelope keystore exists but password is missing");
                }
            }
        }


        dn = getConfiguration().get(KMS_TLS_CERT_DN, "CN=kms");
        // we need to know our own local ip addresses/hostname in order to add them to the ssl cert
        ip = getTrustagentTlsCertIpArray();
        dns = getTrustagentTlsCertDnsArray();
        if (dn == null || dn.isEmpty()) {
            configuration("DN not configured");
        }
        // NOTE: keystore file itself does not need to be checked, we will create it automatically in execute() if it does not exist
        if ((ip == null ? 0 : ip.length) + (dns == null ? 0 : dns.length) == 0) {
            configuration("At least one IP or DNS alternative name must be configured");
        }
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

        try (EnvelopeKeyManager envelopeKeyManager = new EnvelopeKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray())) {
            if (envelopeKeyManager.isEmpty()) {
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

        try (EnvelopeKeyManager envelopeKeyManager = new EnvelopeKeyManager(keystoreType, keystoreFile, keystorePassword.toCharArray())) {
            // create the keypair
            KeyPair keypair = RsaUtil.generateRsaKeyPair(3072);
            X509Builder builder = X509Builder.factory()
                    .selfSigned(dn, keypair)
                    .expires(3650, TimeUnit.DAYS)
                    .keyUsageKeyEncipherment();
            // NOTE:  right now we are creating a self-signed cert but if we have
            //        the mtwilson api url, username, and password, we could submit
            //        a certificate signing request there and have our cert signed
            //        by mtwilson's ca, and then the ssl policy for this host in 
            //        mtwilson could be "signed by trusted ca" instead of
            //        "that specific cert"
            if (ip != null) {
                for (String san : ip) {
                    log.debug("Adding Subject Alternative Name (SAN) with IP address: {}", san);
                    builder.ipAlternativeName(san.trim());
                }
            }
            if (dns != null) {
                for (String san : dns) {
                    log.debug("Adding Subject Alternative Name (SAN) with Domain Name: {}", san);
                    builder.dnsAlternativeName(san.trim());
                }
            }
            X509Certificate cert = builder.build();
            if( cert == null ) {
                for(Fault fault : builder.getFaults()) {
                    log.error("{}: {}", fault.getClass().getName(), fault.getDescription());
                }
                throw new IOException("Cannot create Envelope Key certificate");
            }        

            KeyAttributes keyAttributes = envelopeKeyManager.createEnvelopeKey(keypair.getPrivate(), cert);
            log.debug("Created envelope key with id {}", keyAttributes.getKeyId());

            /**
             * Store the certificate in a separate file so administrator can
             * easily copy it to client systems (like Trust Director) so they
             * can wrap keys when registering with KMS
             *
             */
            FileUtils.write(new File(Folders.configuration() + File.separator + "envelope.pem"), X509Util.encodePemCertificate(cert), Charset.forName("UTF-8"));


        }

        // save the settings in configuration;  DO NOT SAVE MASTER KEY
        getConfiguration().set(EnvelopeKeyManager.ENVELOPE_KEYSTORE_FILE_PROPERTY, keystorePath);
        getConfiguration().set(EnvelopeKeyManager.ENVELOPE_KEYSTORE_TYPE_PROPERTY, keystoreType);
        getConfiguration().set(EnvelopeKeyManager.ENVELOPE_KEYSTORE_PASSWORD_PROPERTY, keystorePasswordAlias);
        getConfiguration().set(KMS_TLS_CERT_DN, dn);
        if (ip != null) {
            getConfiguration().set(KMS_TLS_CERT_IP, StringUtils.join(ip, ","));
        }
        if (dns != null) {
            getConfiguration().set(KMS_TLS_CERT_DNS, StringUtils.join(dns, ","));
        }

    }

    // note: duplicated from TrustagentConfiguration
    public String getTrustagentTlsCertIp() {
        return getConfiguration().get(KMS_TLS_CERT_IP, "");
    }
    // note: duplicated from TrustagentConfiguration

    public String[] getTrustagentTlsCertIpArray() throws SocketException {
//        return getConfiguration().getString(KMS_TLS_CERT_IP, "127.0.0.1").split(",");
        String[] TlsCertIPs = getConfiguration().get(KMS_TLS_CERT_IP, "").split(",");
        if (TlsCertIPs != null && !TlsCertIPs[0].isEmpty()) {
            log.debug("Retrieved IPs from configuration: {}", (Object[]) TlsCertIPs);
            return TlsCertIPs;
        }
        List<String> TlsCertIPsList = NetUtils.getNetworkAddressList(); // never returns null but may be empty
        String[] ipListArray = new String[TlsCertIPsList.size()];
        if (ipListArray.length > 0) {
            log.debug("Retrieved IPs from network configuration: {}", (Object[]) ipListArray);
            return TlsCertIPsList.toArray(ipListArray);
        }
        log.debug("Returning default IP address [127.0.0.1]");
        return new String[]{"127.0.0.1"};
    }
    // note: duplicated from TrustagentConfiguration

    public String getTrustagentTlsCertDns() {
        return getConfiguration().get(KMS_TLS_CERT_DNS, "");
    }
    // note: duplicated from TrustagentConfiguration

    public String[] getTrustagentTlsCertDnsArray() throws SocketException {
//        return getConfiguration().getString(KMS_TLS_CERT_DNS, "localhost").split(",");
        String[] TlsCertDNs = getConfiguration().get(KMS_TLS_CERT_DNS, "").split(",");
        if (TlsCertDNs != null && !TlsCertDNs[0].isEmpty()) {
            log.debug("Retrieved Domain Names from configuration: {}", (Object[]) TlsCertDNs);
            return TlsCertDNs;
        }
        List<String> TlsCertDNsList = NetUtils.getNetworkHostnameList(); // never returns null but may be empty
        String[] dnListArray = new String[TlsCertDNsList.size()];
        if (dnListArray.length > 0) {
            log.debug("Retrieved Domain Names from network configuration: {}", (Object[]) dnListArray);
            return TlsCertDNsList.toArray(dnListArray);
        }
        log.debug("Returning default Domain Name [localhost]");
        return new String[]{"localhost"};
    }
}
