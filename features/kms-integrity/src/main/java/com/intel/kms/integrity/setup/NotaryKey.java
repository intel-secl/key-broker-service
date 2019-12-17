/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.integrity.setup;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.net.NetUtils;
import com.intel.dcsg.cpg.x509.X509Builder;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.Folders;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.integrity.NotaryKeyManager;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_FILE;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_TYPE;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_KEYSTORE_FILE_PROPERTY;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_KEYSTORE_TYPE_PROPERTY;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.commons.io.FileUtils;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_KEYSTORE_PASSWORD_ALIAS_PROPERTY;
import static com.intel.kms.integrity.NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_PASSWORD_ALIAS;

/**
 * Creates a private key and self-signed certificate. The "notary key" is the
 * private key which is used to certify an authorized user's transfer public key
 * as well as create integrity signatures for key metadata. The notary may also
 * generate an HMAC secret key for metadata integrity signatures for improved
 * performance over RSA signatures if administrator requires it.
 *
 * JKS (.jks) provider can only store private keys (asymmetric) JCEKS (.jcs)
 * provider can store private and secret keys but only supports ASCII passwords
 * PCKS12 (.p12) provider can store only private keys and only supports ASCII
 * passwords
 *
 * @author jbuhacoff
 */
public class NotaryKey extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(NotaryKey.class);
    // configuration keys
    private static final String KMS_TLS_CERT_DN = "kms.tls.cert.dn";
    private static final String KMS_TLS_CERT_IP = "kms.tls.cert.ip";
    private static final String KMS_TLS_CERT_DNS = "kms.tls.cert.dns";
    private String keystoreType;
    private String keystorePath;
    private File keystoreFile;
//    private PrivateKeyStore keystore;
    private String keystorePasswordAlias;
    private Password keystorePassword;
    private String dn;
    private String[] ip;
    private String[] dns;

    @Override
    protected void configure() throws Exception {
        Configuration configuration = getConfiguration();
        keystoreType = configuration.get(NOTARY_KEYSTORE_TYPE_PROPERTY, NOTARY_DEFAULT_KEYSTORE_TYPE);
        keystorePath = configuration.get(NOTARY_KEYSTORE_FILE_PROPERTY, NOTARY_DEFAULT_KEYSTORE_FILE);
        keystoreFile = new File(keystorePath);
        keystorePasswordAlias = configuration.get(NOTARY_KEYSTORE_PASSWORD_ALIAS_PROPERTY, NOTARY_DEFAULT_KEYSTORE_PASSWORD_ALIAS);

        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                keystorePassword = passwordVault.get(keystorePasswordAlias);
                if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
                    configuration("Notary keystore password is empty");
                }
            }
        }

        dn = getConfiguration().get(KMS_TLS_CERT_DN, "CN=kms-notary"); //trustagentConfiguration.getTrustagentTlsCertDn();
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
            validation("Notary keystore file not found");
            return;
        }
        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            validation("Notary keystore password not created");
            return;
        }

        try (NotaryKeyManager notaryKeyManager = new NotaryKeyManager(getConfiguration())) {
            if (notaryKeyManager.getKeystore() == null) {
                validation("Notary keystore not created");
            } else if (notaryKeyManager.getKeystore().isEmpty()) {
                validation("Notary keystore is empty");
            }
        } catch (KeyStoreException | IOException e) {
            validation("Cannot open notary keystore", e);
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

        // store any non-default settings we're using
        if (!keystoreType.equals(NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_TYPE)) {
            getConfiguration().set(NotaryKeyManager.NOTARY_KEYSTORE_TYPE_PROPERTY, keystoreType);
        }
        if (!keystorePath.equals(NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_FILE)) {
            getConfiguration().set(NotaryKeyManager.NOTARY_KEYSTORE_FILE_PROPERTY, keystorePath);
        }
        if (!keystorePasswordAlias.equals(NotaryKeyManager.NOTARY_DEFAULT_KEYSTORE_PASSWORD_ALIAS)) {
            getConfiguration().set(NotaryKeyManager.NOTARY_KEYSTORE_PASSWORD_ALIAS_PROPERTY, keystorePasswordAlias);
        }

        try (NotaryKeyManager notaryKeyManager = new NotaryKeyManager(getConfiguration())) {
            if (notaryKeyManager.getKeystore() != null && notaryKeyManager.getKeystore().isEmpty()) {
                // create the keypair
                KeyPair keypair = RsaUtil.generateRsaKeyPair(3072);
                X509Builder builder = X509Builder.factory()
                        .selfSigned(dn, keypair)
                        .expires(3650, TimeUnit.DAYS)
                        .keyUsageCertificateAuthority()
                        .keyUsageDigitalSignature();
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

                // set key ( alias, keypair.getprivate, cert )
                String keyId = (new UUID()).toString();
                notaryKeyManager.getKeystore().set(keyId, keypair.getPrivate(), new Certificate[]{cert});

                /**
                 * Store the certificate in a separate file so administrator can
                 * easily copy it to client systems (like Trust Director) so
                 * they can verify key metadata
                 *
                 */
                FileUtils.write(new File(Folders.configuration() + File.separator + "notary.pem"), X509Util.encodePemCertificate(cert), Charset.forName("UTF-8"));

            }
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
