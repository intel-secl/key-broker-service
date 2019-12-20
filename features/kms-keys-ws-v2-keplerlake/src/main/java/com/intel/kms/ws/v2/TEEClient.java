/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.ws.v2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.net.URL;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

/**
 *
 * @author sshekhex
 */
public class TEEClient extends JaxrsClient {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TEEClient.class);

    public TEEClient(URL url) throws Exception {
        super(JaxrsClientBuilder.factory().url(url).build());
    }

    public TEEClient(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }

    public TEEClient(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }

    public TEEClient(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).tlsConnection(tlsConnection).build());
    }

    public KeyCollection searchKeyProxyCall(String forwardUrl, String digest) {
        LOG.debug("searchKeyProxyCall : forward url = '{}' and digest = '{}'", forwardUrl, digest);
        return getTarget().path("/proxy").request().header("Forward-Http-Method", "GET")
                .header("Forward-URL", forwardUrl).header("Forward-TLS", "tls.certificate.sha256=" + digest)
                .accept(MediaType.APPLICATION_JSON).post(null, KeyCollection.class);
    }

    //public GetKeyAttributesResponse getKeyProxyCall(String forwardUrl, String digest) {
    public Key getKeyProxyCall(String forwardUrl, String digest) {
        LOG.debug("getKeyProxyCall : forward url = '{}' and digest = '{}'", forwardUrl, digest);
        return getTarget().path("/proxy").request().header("Forward-Http-Method", "GET")
                .header("Forward-URL", forwardUrl).header("Forward-TLS", "tls.certificate.sha256=" + digest)
                //.accept(MediaType.APPLICATION_JSON).post(null, GetKeyAttributesResponse.class);
                .accept(MediaType.APPLICATION_JSON).post(null, Key.class);
    }

    public byte[] transferKeyProxyCall(String forwardUrl, String digest, String oauthToken) {
        LOG.debug("transferKeyProxyCall : forward url = '{}' and digest = '{}' and oauthToken = '{}'", forwardUrl, digest, oauthToken);
        return getTarget().path("/proxy").request().header("Forward-Http-Method", "POST")
                .header("Forward-URL", forwardUrl).header("Forward-TLS", "tls.certificate.sha256=" + digest)
                .header("Content-Type", "application/kepler-lake-key-request")
                .header("OAuth2-Authorization", oauthToken)
                .accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity("", "application/kepler-lake-key-request"), byte[].class);
    }

    public byte[] unbind(byte[] encryptedKey) {
        LOG.debug("unbind : encryptedKey = '{}'", encryptedKey);
        return getTarget().path("/tpm/unbind").request().header("Content-Type", MediaType.APPLICATION_OCTET_STREAM)
                .accept(MediaType.APPLICATION_OCTET_STREAM).post(Entity.entity(encryptedKey, MediaType.APPLICATION_OCTET_STREAM), byte[].class);
    }

}
