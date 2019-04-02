/*
 * Copyright (C) 2015 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy.setup;

import com.intel.mtwilson.core.data.bundle.contributors.AbstractImportCertificatesPemToKeystore;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.io.Resource;
import com.intel.kmsproxy.MtWilsonClientConfiguration;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.data.bundle.Contributor;
import com.intel.mtwilson.core.data.bundle.Entry;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Iterator;

/**
 *
 * @author jbuhacoff
 */
public class DataBundleTlsCertificateImport extends AbstractImportCertificatesPemToKeystore implements Contributor {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DataBundleTlsCertificateImport.class);
    public static final String MTWILSON_CONFIGURATION_NAMESPACE = "com.intel.mtwilson.configuration";
    public static final String TLS_FILENAME = "TLS.pem";
    private final MtWilsonClientConfiguration configuration;
    
    public DataBundleTlsCertificateImport() throws IOException {
        this.configuration = new MtWilsonClientConfiguration(ConfigurationFactory.getConfiguration());
    }
    
    @Override
    public Iterator<Entry> contribute() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected String getNamespace() {
        return MTWILSON_CONFIGURATION_NAMESPACE;
    }

    @Override
    protected String getPath() {
        return TLS_FILENAME;
    }

    @Override
    protected Resource getKeystoreResource() {
        String keystorePath = configuration.getKeystorePath();
        File keystoreFile = new File(keystorePath);
        return new FileResource(keystoreFile);
        
    }

    @Override
    protected Password getKeystorePassword() {
        try {
            Password keystorePassword = configuration.getKeystorePassword();
            return keystorePassword;
        }
        catch( KeyStoreException | IOException e) {
            log.error("Cannot get keystore password", e);
            return null;
        }
    }
}
