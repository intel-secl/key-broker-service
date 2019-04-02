/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy.setup;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.net.NetUtils;
import com.intel.kmsproxy.MtWilsonClientConfiguration;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.setup.faults.ConfigurationKeyNotSet;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.v2.client.MwClientUtil;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import org.apache.commons.lang3.StringUtils;

/**
 * Creates a private key and self-signed certificate, registers the certificate
 * with Mt Wilson and requests the "Attestation" role. 
 * 
 * Note that a Mt Wilson administrator needs to approve the access before the
 * keyserver proxy can obtain attestation reports.
 * 
 * @author jbuhacoff
 */
public class MtWilsonClient extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonClient.class);
    // configuration keys
    private static final String KMSPROXY_TLS_CERT_DN = "kmsproxy.tls.cert.dn";
    private static final String KMSPROXY_TLS_CERT_IP = "kmsproxy.tls.cert.ip";
    private static final String KMSPROXY_TLS_CERT_DNS = "kmsproxy.tls.cert.dns";
    private String keystorePath;
    private File keystoreFile;
    private String keystorePasswordAlias;
    private Password keystorePassword;
    private String dn;
    private String[] ip;
    private String[] dns;
    private String mtwilsonUsername;
    private URL mtwilsonUrl;
    private String mtwilsonTlsCertSha256;
    private final ObjectMapper yaml;
    private MtWilsonClientConfiguration configuration;

    public MtWilsonClient() {
        super();
        yaml = createYamlMapper();
    }
    
    @Override
    protected void configure() throws Exception {
        configuration = new MtWilsonClientConfiguration(getConfiguration());
        keystorePath = configuration.getKeystorePath();
//        keystorePath = getConfiguration().get(MtWilsonClientConfiguration.MTWILSON_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "mtwilson.jks");
        keystoreFile = new File(keystorePath);
//        keystoreFile = configuration.getKeystoreFile();
        keystorePasswordAlias = configuration.getKeystorePasswordAlias(); //getConfiguration().get(MtWilsonClientConfiguration.MTWILSON_KEYSTORE_PASSWORD_PROPERTY, "");

        try {
            keystorePassword = configuration.getKeystorePassword();
        }
        catch(KeyStoreException | IOException e) {
            log.error("Cannot open Mt Wilson API client keystore", e);
        }
        if (keystoreFile.exists()) {
            // we only need to know the password if the file already exists
            // if user lost password, delete the file and we can recreate it
            // with a new random password
            if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
                configuration("Mt Wilson client keystore exists but password is missing");
            }
        }

        mtwilsonUsername = configuration.getEndpointUsername();
        if( mtwilsonUsername == null ) {
            mtwilsonUsername = String.format("kmsproxy.%s", new UUID().toHexString());
        }
        
        // if a specific DN is not configured, use "kmsproxy" with a random UUID to avoid collisions when multiple kmsproxy instances
        // register with the same mtwilson
        dn = getConfiguration().get(KMSPROXY_TLS_CERT_DN, String.format("CN=%s", mtwilsonUsername));
        // we need to know our own local ip addresses/hostname in order to add them to the ssl cert
        ip = getTrustagentTlsCertIpArray();
        dns = getTrustagentTlsCertDnsArray();
        if (dn == null || dn.isEmpty()) {
            configuration(new ConfigurationKeyNotSet(KMSPROXY_TLS_CERT_DN)); // "DN not configured"
        }
        // NOTE: keystore file itself does not need to be checked, we will create it automatically in execute() if it does not exist
        if ((ip == null ? 0 : ip.length) + (dns == null ? 0 : dns.length) == 0) {
            configuration("At least one IP or DNS alternative name must be configured");
        }
        
        //mtwilsonUrl = getConfiguration().get(MtWilsonClientConfiguration.MTWILSON_API_URL);
        mtwilsonTlsCertSha256 = getConfiguration().get(MtWilsonClientConfiguration.MTWILSON_TLS_CERT_SHA256);
        
        try {
            //URL url = new URL(mtwilsonUrl);
            mtwilsonUrl = configuration.getEndpointURL();
            log.debug("Mt Wilson URL: {}", (mtwilsonUrl==null?"null":mtwilsonUrl.toExternalForm()));
            if( mtwilsonUrl == null ) {
                configuration(new ConfigurationKeyNotSet(MtWilsonClientConfiguration.MTWILSON_API_URL));
            }
        }
        catch(MalformedURLException e) {
            log.debug("Invalid Mt Wilson URL", e);
            configuration("Invalid Mt Wilson URL: %s", getConfiguration().get(MtWilsonClientConfiguration.MTWILSON_API_URL));
        }

    }

        
    private ObjectMapper createYamlMapper() {
        YAMLFactory yamlFactory = new YAMLFactory();
        yamlFactory.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
        yamlFactory.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
        ObjectMapper mapper = new ObjectMapper(yamlFactory);
        mapper.setPropertyNamingStrategy(new PropertyNamingStrategy.LowerCaseWithUnderscoresStrategy());
        return mapper;
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

        /*
        try (EnvelopeKeyManager envelopeKeyManager = new EnvelopeKeyManager(keystoreFile, keystorePassword)) {
            if (envelopeKeyManager.isEmpty()) {
                validation("Keystore is empty");
            }
        } catch (KeyStoreException | IOException e) {
            validation("Cannot read storage key", e);
        }
        * */
    }
    
    
    private static class UserComment {
        public HashSet<String> roles = new HashSet<>();
    }
    
    private String formatCommentRequestedRoles(String... roles) throws JsonProcessingException {
        UserComment userComment = new UserComment();
        userComment.roles.addAll(Arrays.asList(roles));
        return yaml.writeValueAsString(userComment);
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

        FileResource resource = new FileResource(keystoreFile);
        Properties p = new Properties();
//        p.setProperty("mtwilson.api.url", mtwilsonUrl); // past bug in MwClientUtil required us to set this, but now it uses the URL we pass in as a parameter
        p.setProperty("mtwilson.api.tls.policy.certificate.sha256", mtwilsonTlsCertSha256);
//        TlsPolicy tlsPolicy = PropertiesTlsPolicyFactory.createTlsPolicy(p);
//        KeystoreUtil.createUserInResource(resource, mtwilsonUsername, new String(keystorePassword.toCharArray()), new URL(mtwilsonUrl), tlsPolicy, new String[] { "Attestation" }, "TLS");

        String comment = formatCommentRequestedRoles("Attestation", "Challenger");
        
        /**
         * The Mt Wilson API URL is in this form:  https://mtwilson:8443/mtwilson
         * The createUserInResourceV2 method needs the /v2 path appended to it.
         */
        URL v2 = new URL(String.format("%s/v2",mtwilsonUrl.toExternalForm()));
        MwClientUtil.createUserInResourceV2(resource, mtwilsonUsername, new String(keystorePassword.toCharArray()), v2, p, comment, Locale.getDefault(), "TLS");
        
        /*
        try (EnvelopeKeyManager envelopeKeyManager = new EnvelopeKeyManager(keystoreFile, keystorePassword)) {
            // create the keypair
            KeyPair keypair = RsaUtil.generateRsaKeyPair(2048);
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

            // set key ( alias, keypair.getprivate, cert )
            envelopeKeyManager.createEnvelopeKey(keypair.getPrivate(), cert);

//             * Store the certificate in a separate file so administrator can
//             * easily copy it to client systems (like Trust Director) so they
//             * can wrap keys when registering with KMS
//             *
//            FileUtils.write(new File(Folders.configuration() + File.separator + "envelope.pem"), X509Util.encodePemCertificate(cert), Charset.forName("UTF-8"));


        }
    */

        // save the settings in configuration;  DO NOT SAVE MASTER KEY
        getConfiguration().set(MtWilsonClientConfiguration.MTWILSON_USERNAME, mtwilsonUsername);
        getConfiguration().set(MtWilsonClientConfiguration.MTWILSON_KEYSTORE_FILE_PROPERTY, keystorePath);
        getConfiguration().set(MtWilsonClientConfiguration.MTWILSON_KEYSTORE_PASSWORD_PROPERTY, keystorePasswordAlias);
        getConfiguration().set(MtWilsonClientConfiguration.MTWILSON_API_URL, mtwilsonUrl.toExternalForm());
        getConfiguration().set(MtWilsonClientConfiguration.MTWILSON_TLS_CERT_SHA256, mtwilsonTlsCertSha256);
        getConfiguration().set(KMSPROXY_TLS_CERT_DN, dn);
        if (ip != null) {
            getConfiguration().set(KMSPROXY_TLS_CERT_IP, StringUtils.join(ip, ","));
        }
        if (dns != null) {
            getConfiguration().set(KMSPROXY_TLS_CERT_DNS, StringUtils.join(dns, ","));
        }

    }

    // note: duplicated from TrustagentConfiguration
    public String getTrustagentTlsCertIp() {
        return getConfiguration().get(KMSPROXY_TLS_CERT_IP, "");
    }
    // note: duplicated from TrustagentConfiguration

    public String[] getTrustagentTlsCertIpArray() throws SocketException {
//        return getConfiguration().getString(KMS_TLS_CERT_IP, "127.0.0.1").split(",");
        String[] TlsCertIPs = getConfiguration().get(KMSPROXY_TLS_CERT_IP, "").split(",");
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
        return getConfiguration().get(KMSPROXY_TLS_CERT_DNS, "");
    }
    // note: duplicated from TrustagentConfiguration

    public String[] getTrustagentTlsCertDnsArray() throws SocketException {
//        return getConfiguration().getString(KMS_TLS_CERT_DNS, "localhost").split(",");
        String[] TlsCertDNs = getConfiguration().get(KMSPROXY_TLS_CERT_DNS, "").split(",");
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

    /**
     * Converts the given byte[] array to a char[] array, storing one byte per
     * character. The length of the resulting char[] array should be the same as
     * the length of the input byte[] array.
     *
     * @param byteArray
     * @return
     */
    /*
    private char[] toCharArray(byte[] byteArray) {
        char[] charArray = new char[byteArray.length];
        for (int i = 0; i < byteArray.length; i++) {
            charArray[i] = (char) (byteArray[i] & 0xff);
        }
        return charArray;
    }
    */
}
