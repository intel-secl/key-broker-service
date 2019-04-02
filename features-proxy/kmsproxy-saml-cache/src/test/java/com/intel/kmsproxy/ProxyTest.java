/*
 * Copyright (C) 2015 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.io.PropertiesUtil;
import com.intel.mtwilson.core.junit.Env;
import java.io.IOException;
import java.nio.charset.Charset;
import org.apache.commons.io.IOUtils;
import java.io.InputStream;
import java.util.Properties;
import org.junit.Test;
import com.intel.mtwilson.jaxrs2.client.MtWilsonClient;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.tls.policy.creator.impl.InsecureTlsPolicyCreator;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyCreator;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.junit.BeforeClass;

/**
 *
 * @author jbuhacoff
 */
public class ProxyTest {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProxyTest.class);

    @BeforeClass
    public static void registerExtensions() {
        WhiteboardExtensionProvider.register(TlsPolicyCreator.class, InsecureTlsPolicyCreator.class);
    }

    private String getAIK() throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/aik51.pem")) {
            return IOUtils.toString(in, Charset.forName("UTF-8"));
        }
    }

    private String getSAML() throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/saml51.xml")) {
            return IOUtils.toString(in, Charset.forName("UTF-8"));
        }
    }

    /**
     * Sends a request like this:
     *
     * <pre>
     * POST http://10.1.71.74:8080/v1/keys/86bcdec3-b553-4665-b21e-baa70a7bd376/transfer
     * Accept: application/octet-stream
     * Content-Type: application/x-pem-file
     * -----BEGIN CERTIFICATE-----
     * MIICvTCCAaWgAwIBAgIGAVHKNzbKMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMT
     * EG10d2lsc29uLXBjYS1haWswHhcNMTUxMjIyMTUwMzE0WhcNMjUxMjIxMTUwMzE0
     * WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1TqoeRXFaJTPpiFE
     * kaNJ0f/em0Wz9fTnk+Vffg0f9Buw2xE/jjlzxR3/Bq0L7+fRwrMasprGlwMaR4gB
     * Yumc1gl3y2YZbJ7m7VjsnC58G8iZfmeIpbGXsp3hdrmIF/0f77k4wbqUJZubeff0
     * KuSTzjZSvAIiisi3KDjor4ivzUZF8RT3cKrNz7IqHvXBhdYMZEl6FhQiRVs1MaGn
     * PrszNDcYCHaiL+fzkHlntxaKeS9qeReeCyP0gspx6oggAyiO1Az80fWOS3YQ5C/v
     * fmMSdJqVBXonFQKlU+dQInnIlwN8BjgaWNpJrcbWARyCFIQPP/g1vmwbToK0boGa
     * ni9QDQIDAQABoyIwIDAeBgNVHREBAf8EFDASgRBISVMgSWRlbnRpdHkgS2V5MA0G
     * CSqGSIb3DQEBBQUAA4IBAQCOFdWSEbiZXmmZChfJ8yulrUwoER7wU+wuFSJNfJxl
     * YzuBellekHAx+4SwafwCnGgBUYv2i/0fqGm4sJw90O6f90elR+w4997frJaeTU+E
     * /v44oGWta+FHqhsGNQZ5YGGAMM+Jsrw+/1gwJkchkMXRhuqr3AsMaurh1maMH8u5
     * WNn9rw4O3cCSS2Is1pY+xHSjwdlZMLPwk2BS2n6sbZDVIr2WIXv2X74Ck/u/6puk
     * w3cyXzswUivljHIhAAOM7kz+WrK9UXxzObMQaj47BnoTkS5oyuh05DJIiDRuMaVt
     * lYKgM8SL8JElZyYKqy3IRk75JJNeCwnW9zKNIMzE55O9
     * -----END CERTIFICATE-----
     * </pre>
     *
     * Required configuration:
     * cit3.keybroker.endpoint.url
     * cit3.keybroker.proxy.host
     * cit3.keybroker.proxy.port
     * 
     * 66:  1f843926-6ec0-47e5-8950-97f181680458
     * 51:  7e498cd8-8220-4bcc-947f-9310a39b8874
     * 
     * @throws Exception
     */
    @Test
    public void testKeyBrokerProxy() throws Exception {
        String aik = getAIK();
        Properties properties = PropertiesUtil.removePrefix(Env.getProperties("cit3-keybroker-proxy"), "cit3.keybroker.");

        MtWilsonClient client = new MtWilsonClient(properties);
        byte[] result = client.getTarget().path("/v1/keys/86bcdec3-b553-4665-b21e-baa70a7bd376/transfer").request(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(aik, CryptoMediaType.APPLICATION_X_PEM_FILE), byte[].class);
        log.debug("result: {}", result);
    }

    /**
     * Send a request like:
     * <pre>
     * POST http://10.1.71.73/v1/keys/86bcdec3-b553-4665-b21e-baa70a7bd376/transfer
     * Accept: application/octet-stream
     * Content-Type: application/samlassertion+xml
     * <?xml version="1.0" encoding="UTF-8"?>
     * (saml xml here)
     * </pre>
     *
     * Successful response:
     * <pre>
     * 200
     * Key-ID: 86bcdec3-b553-4665-b21e-baa70a7bd376
     * Content-Length: 256
     * Content-Type: application/octet-stream
     * Server: Jetty(9.1.1.v20140108)
     * (binary encrypted key material here)
     * </pre>
     *
     * Required configuration:
     * cit3.keybroker.endpoint.url
     * 
     * @throws Exception
     */
    @Test
    public void testKeyBroker() throws Exception {
        String saml = getSAML();
        Properties properties = PropertiesUtil.removePrefix(Env.getProperties("cit3-keybroker"), "cit3.keybroker.");

        MtWilsonClient client = new MtWilsonClient(properties);
        byte[] result = client.getTarget().path("/v1/keys/1f843926-6ec0-47e5-8950-97f181680458/transfer").request(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(saml, CryptoMediaType.APPLICATION_SAML), byte[].class);
        log.debug("result: {}", result);
    }
    
    
}
