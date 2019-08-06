/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.io.PropertiesUtil;
//import com.intel.mtwilson.as.rest.v2.model.HostAttestationFilterCriteria;
//import com.intel.mtwilson.attestation.client.jaxrs.HostAttestations;
import com.intel.mtwilson.core.junit.Env;
import com.intel.mtwilson.tls.policy.creator.impl.CertificateDigestTlsPolicyCreator;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyCreator;
import java.io.IOException;
import java.util.Properties;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jbuhacoff
 */
public class MtWilsonV2ClientTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonV2ClientTest.class);

    @BeforeClass
    public static void registerExtensions() {
        WhiteboardExtensionProvider.register(TlsPolicyCreator.class, CertificateDigestTlsPolicyCreator.class);
    }
    
    /**
     * How to get mtwilson.tls.cert.sha256:
     * sha256sum /opt/mtwilson/configuration/ssl.crt
     * 
     * How to get username and password:
     * mtwilson login-password username password --permissions *:*
     * 
     * How to get AIK PUBLIC KEY SHA1 from compute node:
     * openssl x509 -in /opt/trustagent/configuration/aik.pem -inform pem -out /dev/null -pubkey > ~/aik.pubkey.pem
     * openssl rsa -pubin -in ~/aik.pubkey.pem -inform pem  -pubout -out ~/aik.pubkey.der -outform der 
     * sha1sum ~/aik.pubkey.der
     * 
     * Note that the AIK PUBLIC KEY SHA1 is the sha1 of the public key in DER format,
     * NOT of the aik X509 certificate.
     * 
     * The MtWilsonV2Client takes the "mtwilson." prefix out of the properties before
     * constructing the HostAttestations client
     * 
     * Required configuration:
     * cit3.attestation.endpoint.url
     * cit3.attestation.login.basic.username
     * cit3.attestation.login.basic.password
     * cit3.attestation.tls.policy.certificate.sha1
     * 
     */
    //@Test
   // public void testGetOrPostSamlRequestToAttestationService() throws IOException {
   //     Properties attestation = PropertiesUtil.replacePrefix(Env.getProperties("cit3-attestation"), "cit3.attestation.", "mtwilson.");
   //     PropertiesConfiguration c = new PropertiesConfiguration(attestation);
   //     MtWilsonV2Client client = new MtWilsonV2Client(c);
   //     String saml = client.getAssertionForSubject("9080c913c570f4a56c00b36bf1598ff184e15677"); // 10.1.70.51   pub key sha1 is : 9080c913c570f4a56c00b36bf1598ff184e15677
   //     log.debug("Result: {}", saml);
   // }
    
    /**
     * The HostAttestations client takes the properties without the "mtwilson." prefix
     * because it uses a generic JAX-RS client builder
     * 
     * Success response:  the SAML assertion in XML
     * 
     * Failure response (no cached SAML for the host): 
     * <pre>
204
Date: Sun, 17 Jan 2016 07:33:54 GMT
Set-Cookie: rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Sat, 16-Jan-2016 07:33:54 GMT,rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Sat, 16-Jan-2016 07:33:54 GMT,JSESSIONID=6F1BF93134CF514ADDD4C354524E5BA9; Path=/mtwilson/; Secure; HttpOnly,rememberMe=deleteMe; Path=/mtwilson; Max-Age=0; Expires=Sat, 16-Jan-2016 07:33:54 GMT
Server: Apache-Coyote/1.1
     * </pre>
     * 
     * Required configuration:
     * cit3.attestation.endpoint.url
     * cit3.attestation.login.basic.username
     * cit3.attestation.login.basic.password
     * cit3.attestation.tls.policy.certificate.sha1
     * 
     * @throws Exception 
     */
    //@Test
   // public void testGetTrustReportFromAttestationService() throws Exception {
   //     Properties properties = PropertiesUtil.removePrefix(Env.getProperties("cit3-attestation"), "cit3.attestation.");
   //     HostAttestationFilterCriteria criteria = new HostAttestationFilterCriteria();
   //criteria.aikPublicKeySha256 = "f59b391c32796828ea885ec7066237492443a09fa7e0e21d1fea864799469f0d";
   //    HostAttestations client = new HostAttestations(properties);
   //     String saml = client.searchHostAttestationsSaml(criteria);
   //     log.debug("SAML: {}", saml);
        
//    }
}
