/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.keplerlake;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.net.URL;
import java.util.Properties;

/**
 *
 * @author sshekhex
 */
public class KeplerlakeClient extends JaxrsClient {
    
    public KeplerlakeClient(URL url) throws Exception {
        super(JaxrsClientBuilder.factory().url(url).build());
    }

    public KeplerlakeClient(Properties properties) {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public KeplerlakeClient(Configuration configuration) {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    public KeplerlakeClient(Properties properties, TlsConnection tlsConnection) {
        super(JaxrsClientBuilder.factory().configuration(properties).tlsConnection(tlsConnection).build());
    }
    
}
