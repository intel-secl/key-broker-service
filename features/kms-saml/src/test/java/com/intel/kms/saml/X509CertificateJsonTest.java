/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.kms.saml.jaxrs.SamlCertificateRepository;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.tag.model.Certificate;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class X509CertificateJsonTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(X509CertificateJsonTest.class);
    private static X509Certificate certificate;
    
    @BeforeClass
    public static void readCertificate() throws IOException, CertificateException {
        certificate = X509Util.decodePemCertificate(IOUtils.toString(X509CertificateSearchTest.class.getResourceAsStream("/saml_certificate.pem"), Charset.forName("UTF-8")));
    }

    @Test
    public void testSerializeCertificate() throws JsonProcessingException, IOException, KeyStoreException, CertificateEncodingException {
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        SamlCertificateRepository repository = new SamlCertificateRepository(); // throws IOException, KeyStoreException
        Certificate document = repository.toDocument(certificate); // throws CertificateEncodingException
        log.debug("Certificate: {}", mapper.writeValueAsString(document)); // throws JsonProcessingException
    }
}
