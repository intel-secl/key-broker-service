/*
 * Copyright (C) 2015 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.tpm.identity.setup;

import com.intel.mtwilson.core.data.bundle.contributors.AbstractImportCertificatesPemToKeystore;
import com.intel.kms.saml.setup.*;
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
public class DataBundleTpmIdentityCertificateImport extends AbstractImportCertificatesPemToKeystore implements Contributor {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DataBundleSamlCertificateImport.class);
    public static final String MTWILSON_CONFIGURATION_NAMESPACE = "com.intel.mtwilson.configuration";
    public static final String TPM_IDENTITY_FILENAME = "PrivacyCA.pem";
    private final TpmIdentityCertificates setup;
    
    public DataBundleTpmIdentityCertificateImport() {
        this.setup = new TpmIdentityCertificates();
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
        return TPM_IDENTITY_FILENAME;
    }

    @Override
    protected Resource getKeystoreResource() {
        File keystoreFile = setup.getTpmIdentityCertificatesKeystoreFile();
        return new FileResource(keystoreFile);
    }

    @Override
    protected Password getKeystorePassword() {
        try {
                    Password keystorePassword = setup.getTpmIdentityCertificatesKeystorePassword();
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
