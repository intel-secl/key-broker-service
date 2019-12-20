/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keplerlake;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.MapConfiguration;
import com.intel.dcsg.cpg.crypto.key.HKDF;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.http.MutableQuery;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.dcsg.cpg.tls.policy.impl.InsecureTlsPolicy;
import com.intel.keplerlake.io.Etcdctl3;
import com.intel.keplerlake.notary.RsaNotary;
import com.intel.keplerlake.registry.ext.KeplerLakeRegistryDAO;
import com.intel.keplerlake.registry.ext.TrustAgentProxyClient;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;

/**
 *
 * @author SSHEKHEX
 */
public class KeplerLakeUtil {
    
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(KeplerLakeUtil.class);
    private final Configuration configuration;
    public final String realm;
    private final KeplerLakeRegistryDAO dao;
    
    public KeplerLakeUtil() throws IOException {
        this.configuration = ConfigurationFactory.getConfiguration();
        this.realm = configuration.get("SYSTEM_REALM");
        this.dao = new KeplerLakeRegistryDAO(new Etcdctl3(), realm);
    }
    public KeplerLakeUtil(Configuration configuration) {
        this.configuration = configuration;
        this.realm = configuration.get("SYSTEM_REALM");
        this.dao = new KeplerLakeRegistryDAO(new Etcdctl3(), realm);
    }
    public Properties tdcConfiguration() throws IOException {
        Configuration tdc = ConfigurationFactory.getConfiguration();
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = getDaoInstance();
        if (keplerLakeRegistryDAO != null) {
            tdc = new MapConfiguration(keplerLakeRegistryDAO.getTDCService().map());
        }
        Properties properties = getDefaultProperties();
        properties.setProperty("endpoint.url", tdc.get("url"));
        properties.setProperty("tls.policy.certificate.sha256", tdc.get("tls.certificate.sha256")); // example: 67b11ba1b71670588ccc9b5aa1fb8c0c2fc81714
        return properties;
    }
    
    public Properties oAuthConfiguration() throws IOException {
        Configuration oauth2 = ConfigurationFactory.getConfiguration();
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = getDaoInstance();
        if (keplerLakeRegistryDAO != null) {
            oauth2 = new MapConfiguration(keplerLakeRegistryDAO.getOAuth2Service().toMap());
        }
        Properties properties = getDefaultProperties();
        properties.setProperty("endpoint.url", oauth2.get("url"));
        properties.setProperty("tls.policy.certificate.sha256", oauth2.get("tls.certificate.sha256")); // example: 67b11ba1b71670588ccc9b5aa1fb8c0c2fc81714
        return properties;
    }

    /**
     * Read etcd Configuration Details.
     *
     * @return
     * @throws IOException
     */
    public Properties getEtcdConfiguration() throws IOException {
        Properties properties = new Properties();
        Configuration config = ConfigurationFactory.getConfiguration();
        properties.setProperty("endpoint.url", config.get("ETCD_ENDPOINT_URL"));
        properties.setProperty("etcd.cacert.path", config.get("ETCD_CACERT_PATH"));
        properties.setProperty("realm.name", config.get("SYSTEM_REALM"));
        return properties;
    }
    
    /**
     * This method is used to prepare envmap for etcd
     * @return
     * @throws IOException
     */
    
    public Map<String, String> getEnvMap() throws IOException {
        Map<String, String> envMap = new HashMap();
        Configuration config = ConfigurationFactory.getConfiguration();
        envMap.put("ETCDCTL_ENDPOINTS", config.get("ETCD_ENDPOINT_URL"));
        envMap.put("ETCDCTL_CACERT", config.get("ETCD_CACERT_PATH"));
        return envMap;
    }
    
    /**
     * This method is used to return the instance
     * @return 
     */
    public KeplerLakeRegistryDAO getDaoInstance() {
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = null;
        Etcdctl3 etcdctl3;
        LOG.debug("getDaoInstance in keplerlake");
        try {
            etcdctl3 = new Etcdctl3(getEnvMap());
            LOG.debug("realm in keplerlake:{}", this.realm);
            keplerLakeRegistryDAO = new KeplerLakeRegistryDAO(etcdctl3, this.realm);
        } catch (IOException ex) {
            LOG.error("Failed to get the dao instance :{}", ex);
        }
        return keplerLakeRegistryDAO;
    }
    
     /**
     * This method is used to return the instance
     * @param realm
     * @return 
     */
    public KeplerLakeRegistryDAO getDaoInstanceWithRealm(String realm) {
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = null;
        Etcdctl3 etcdctl3;
        LOG.debug("getDaoInstanceWithRealm in keplerlake");
        try {
            etcdctl3 = new Etcdctl3(getEnvMap());
            LOG.debug("with realm in keplerlake:{}", realm);
            keplerLakeRegistryDAO = new KeplerLakeRegistryDAO(etcdctl3,realm);
        } catch (IOException ex) {
            LOG.error("Failed to get the dao instance :{}", ex);
        }
        return keplerLakeRegistryDAO;
    }
    
      /**
     * This method is used to return the instance with data center realm
     * @return 
     */
    public KeplerLakeRegistryDAO getDaoInstanceWithTagentClient() {
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = null;
        Etcdctl3 etcdctl3;
        LOG.debug("getDaoInstanceWithTagentClient in keplerlake");
        try {
            etcdctl3 = new Etcdctl3(getEnvMap());
           TlsConnection tlsConnection = new TlsConnection(new URL(String.format("https://%s:%d/v2", "127.0.0.1", 1443)),
                    new InsecureTlsPolicy());
            TrustAgentProxyClient trustAgentProxyClient = new TrustAgentProxyClient(new Properties(), tlsConnection);
            LOG.debug("realm in keplerlake:{}", this.realm);
            keplerLakeRegistryDAO = new KeplerLakeRegistryDAO(etcdctl3, trustAgentProxyClient, this.realm);
        } catch (Exception ex) {
            LOG.error("Failed to get the dao instance :{}", ex);
        }
        return keplerLakeRegistryDAO;
    }

 /**
     * This method is used to return the instance with requested realm
     * @param realmName
     * @return 
     */
    public KeplerLakeRegistryDAO getDaoInstanceWithTagentClient(String realmName) {
        KeplerLakeRegistryDAO keplerLakeRegistryDAO = null;
        Etcdctl3 etcdctl3;
        LOG.debug("getDaoInstanceWithTagentClient in keplerlake with realm");
        try {
            etcdctl3 = new Etcdctl3(getEnvMap());
           TlsConnection tlsConnection = new TlsConnection(new URL(String.format("https://%s:%d/v2", "127.0.0.1", 1443)),
                    new InsecureTlsPolicy());
            TrustAgentProxyClient trustAgentProxyClient = new TrustAgentProxyClient(new Properties(), tlsConnection);
            LOG.debug("with realm in keplerlake:{}", realmName);
            keplerLakeRegistryDAO = new KeplerLakeRegistryDAO(etcdctl3, trustAgentProxyClient, realmName);
        } catch (Exception ex) {
            LOG.error("Failed to get the dao instance :{}", ex);
        }
        return keplerLakeRegistryDAO;
    }  
    public Properties getDefaultProperties() throws IOException {
       Configuration defaultConfig = ConfigurationFactory.getConfiguration();
        Properties properties = new Properties();
        properties.setProperty("retry.max", defaultConfig.get("MAX_RETRY"));
        properties.setProperty("retry.backoff.constant", defaultConfig.get("BACKOFF_CONSTANT"));
        properties.setProperty("retry.backoff.exponential.max", defaultConfig.get("BACKOFF_EXPONENTIAL"));
        properties.setProperty("retry.backoff.random.min", defaultConfig.get("BACKOFF_RANDOM_MIN"));
        properties.setProperty("retry.backoff.random.max", defaultConfig.get("BACKOFF_RANDOM_MAX"));
        return properties;
    }
    
    public RsaNotary getNotary() throws IOException, KeyStoreException {
       String keystorePasswordAlias="kpl-signature";
       Password keystorePassword = null;
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                LOG.debug("Notary found keystore password with alias {}", keystorePasswordAlias);
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
        }
        
        String keystoreType = "MTWKS"; // or "MTWKS" when it's corrected, see bug #7635
        File keystoreFile = new File(Folders.configuration() + File.separator + "kpl-signature.mtwks" /* or .mtwks when it's corrected */);
        PrivateKeyStore keystore = new PrivateKeyStore(keystoreType, new FileResource(keystoreFile), keystorePassword);
        PrivateKey privateKey = keystore.getPrivateKey("userSignatureKey"); // this alias is hard-coded in policy editor for user signature keys, keep it
        RsaNotary notary = new RsaNotary(privateKey);
        return notary;
    }
    
    public String getISOTimeZone() {
        TimeZone tz = TimeZone.getTimeZone("UTC");
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(tz);
        return df.format(new Date());
    }
    
    public byte[] deriveKey(byte[] masterKey, byte[] salt, String context, CipherKeyAttributes masterKeyAttributes, 
            CipherKeyAttributes derivedKeyAttributes) throws NoSuchAlgorithmException, InvalidKeyException {
        String derivationAlgorithm = masterKeyAttributes.getAlgorithm();
        if (derivationAlgorithm != null && derivationAlgorithm.equals("HKDF")) {
            HKDF hkdf = new HKDF("SHA256");
            MutableQuery query = new MutableQuery();
            query.add("keyuse", "encryption");
            query.add("context", context);
            query.add("algorithm", derivedKeyAttributes.getAlgorithm());
            if(derivedKeyAttributes.getMode() != null && !derivedKeyAttributes.getMode().isEmpty()){
                query.add("mode", derivedKeyAttributes.getMode());
            }
            Integer keyLengthBits = derivedKeyAttributes.getKeyLength();
            query.add("length", String.valueOf(keyLengthBits));
            byte[] info = query.toString().getBytes(Charset.forName("UTF-8"));
            LOG.debug("derived key info: {}", query.toString());
            byte[] derivedKey = hkdf.deriveKey(salt, masterKey, hkdf.getDigestLengthBytes(), info);  // #6304 salt should be hashlen bytes
            LOG.debug("derived key length: {}", derivedKey.length);
            return derivedKey;
        } else {
            throw new UnsupportedOperationException("Unsupported key derivation algorithm: " + derivationAlgorithm);
        }
    }
    
}
