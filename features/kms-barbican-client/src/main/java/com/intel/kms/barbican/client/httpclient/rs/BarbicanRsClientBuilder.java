/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.net.MalformedURLException;
import java.net.URL;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

/**
 *
 * @author GS-0681
 */
public class BarbicanRsClientBuilder {

    private URL url = null;
    private Configuration configuration;

    private BarbicanRsClientBuilder() {
    }

    public static BarbicanRsClientBuilder factory() {
        return new BarbicanRsClientBuilder();
    }

    public BarbicanRsClient build() throws BarbicanClientException {
        try {
            url();
            Client client = ClientBuilder.newBuilder().build();
            WebTarget target = client.target(url.toExternalForm());
            return new BarbicanRsClient(client, target);
        } catch (MalformedURLException ex) {
            throw new BarbicanClientException("Cannot construct rest client", ex);
        }
    }

    private void url() throws MalformedURLException {
        if (url == null) {
            if (configuration != null) {
                url = new URL(configuration.get("barbican.endpoint.url")); // example: "http://localhost:8080/";
            }
        }
    }

    public BarbicanRsClientBuilder configuration(Configuration configuration) {
        this.configuration = configuration;
        return this;
    }
}
