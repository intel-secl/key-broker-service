/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStoreException;

/**
 *
 * @author jbuhacoff
 */
public class MtWilsonClientConfiguration {
    public static final String MTWILSON_TLS_CERT_SHA256 = "mtwilson.tls.cert.sha256";
    public static final String MTWILSON_KEYSTORE_PASSWORD_PROPERTY = "mtwilson.keystore.password";
    public static final String MTWILSON_KEYSTORE_FILE_PROPERTY = "mtwilson.keystore.file";
    // constants
    public static final String MTWILSON_USERNAME = "mtwilson.api.username";
    public static final String MTWILSON_API_URL = "mtwilson.api.url";
    public static final String MTWILSON_PASSWORD = "mtwilson.api.password";
    private Configuration configuration;

    public MtWilsonClientConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    public String getKeystorePath() {
        return configuration.get(MTWILSON_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "mtwilson.jks");
    }
    public File getKeystoreFile() {
        return new File(getKeystorePath());
    }
    
    public String getKeystorePasswordAlias() {
        return configuration.get(MTWILSON_KEYSTORE_PASSWORD_PROPERTY, "mtwilson_keystore_password");
    }

    public String getMtwilsonSHACert(){
        return configuration.get(MTWILSON_TLS_CERT_SHA256);
    }
    
    /**
     * 
     * @return password or null
     */
    public Password getKeystorePassword() throws IOException, KeyStoreException {
        String alias = getKeystorePasswordAlias();
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(alias)) {
                return passwordVault.get(alias);
            }
            return null;
        }        
    }
    
    /**
     * For example, it could be https://example.com/mtwilson
     * 
     * @return the endpoint URL or null if not configured
     * @throws MalformedURLException if the endpoint URL is configured but is not a valid URL
     */
    public URL getEndpointURL() throws MalformedURLException {
        String url = configuration.get(MTWILSON_API_URL);
        if( url == null ) { return null; }
        return new URL(url);
    }
    
    public String getEndpointUsername() {
        return configuration.get(MTWILSON_USERNAME); // no default value, each kms-proxy will generate a unique username to avoid conflicts 
    }
    
    public String getEndpointPassword() {
        return configuration.get(MTWILSON_PASSWORD); 
    }

//    public String getDefaultEndpointUsername() { return "kms-proxy"; }
}
