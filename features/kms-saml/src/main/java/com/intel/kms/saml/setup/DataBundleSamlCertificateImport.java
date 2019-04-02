/*
 * Copyright (C) 2015 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml.setup;

import com.intel.dcsg.cpg.crypto.digest.Digest;
import com.intel.mtwilson.core.data.bundle.contributors.AbstractImportCertificatesPemToKeystore;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.io.Resource;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.mtwilson.core.data.bundle.Contributor;
import com.intel.mtwilson.core.data.bundle.Entry;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 *
 * @author jbuhacoff
 */
public class DataBundleSamlCertificateImport extends AbstractImportCertificatesPemToKeystore implements Contributor {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DataBundleSamlCertificateImport.class);
    public static final String MTWILSON_CONFIGURATION_NAMESPACE = "com.intel.mtwilson.configuration";
    public static final String SAML_FILENAME = "SAML.pem";
    private final SamlCertificates setup;
    
    public DataBundleSamlCertificateImport() {
        this.setup = new SamlCertificates();
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
        return SAML_FILENAME;
    }

    @Override
    protected Resource getKeystoreResource() {
        File keystoreFile = setup.getSamlCertificatesKeystoreFile();
        return new FileResource(keystoreFile);
    }

    @Override
    protected Password getKeystorePassword() {
        try {
                    Password keystorePassword = setup.getSamlCertificatesKeystorePassword();
                    return keystorePassword;
        }
        catch( KeyStoreException | IOException e) {
            log.error("Cannot get keystore password", e);
            return null;
        }
    }
    
    @Override
    protected String getAlias(X509Certificate certificate) throws CertificateEncodingException {
        return UUID.valueOf(java.util.UUID.randomUUID()).toString();
    }
    
}
