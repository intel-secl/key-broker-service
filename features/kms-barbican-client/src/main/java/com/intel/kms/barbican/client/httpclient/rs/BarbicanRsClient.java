/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;

/**
 *
 * @author jbuhacoff
 */
public class BarbicanRsClient {

    private Client client;
    private WebTarget target;

    /**
     * Creates a client using an existing configured JAX-RS client and a
     * specified web target.
     *
     * @param client
     * @param target
     */
    public BarbicanRsClient(Client client, WebTarget target) {
        this.client = client;
        this.target = target;
    }

    /**
     * Creates a new client instance using an existing configured client and web
     * target combination.
     *
     * @param jaxrsClient
     */
    public BarbicanRsClient(BarbicanRsClient jaxrsClient) {
        this.client = jaxrsClient.getClient();
        this.target = jaxrsClient.getTarget();
    }

    public Client getClient() {
        return client;

    }

    public WebTarget getTarget() {
        return target;
    }

    public WebTarget getTargetPath(String path) {
        return target.path(path);
    }

}
