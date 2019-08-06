/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.saml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.kms.saml.jaxrs.SamlCertificateRepository;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.supplemental.saml.TrustAssertion;
import com.intel.mtwilson.supplemental.saml.TrustAssertion.HostTrustAssertion;
import com.intel.mtwilson.tag.model.Certificate;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jbuhacoff
 */
public class SamlVerificationTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlVerificationTest.class);
    private static X509Certificate certificate;
    private static String report;
    
    @BeforeClass
    public static void readCertificate() throws IOException, CertificateException {
        certificate = X509Util.decodePemCertificate(IOUtils.toString(X509CertificateSearchTest.class.getResourceAsStream("/saml_certificate.pem"), Charset.forName("UTF-8")));
        report = IOUtils.toString(SamlVerificationTest.class.getResourceAsStream("/saml_report_with_binding_key.xml"), Charset.forName("UTF-8"));
    }

    @Test
    public void testSerializeCertificate() throws JsonProcessingException, IOException, GeneralSecurityException {
        TrustAssertion assertion = new TrustAssertion(new X509Certificate[] { certificate }, report);
        log.debug("Assertion is valid? {}", assertion.isValid());
        assertTrue(assertion.isValid());
        Set<String> hosts = assertion.getHosts();
        log.debug("Assertion is for hosts: {}", hosts);
        for(String host : hosts) {
            HostTrustAssertion hostTrust = assertion.getTrustAssertion(host);
            X509Certificate aikCertificate = hostTrust.getAikCertificate();
            log.debug("Got aik? {}", aikCertificate);
            X509Certificate bindingKeyCertificate = hostTrust.getBindingKeyCertificate();
            log.debug("Got binding key? {}", bindingKeyCertificate);
            bindingKeyCertificate.verify(certificate.getPublicKey());
            log.debug("Binding key verified by saml certificate");
        }
    }
}
