/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author GS-0681
 */
public class BarbicanOperation extends BarbicanRsClient {

    protected static final Logger LOG = LoggerFactory.getLogger(BarbicanOperation.class);
    protected static String xProjectID = null;
    protected static BarbicanAuthToken barbAuthToken = null; 

    public BarbicanOperation(Configuration configuration) throws BarbicanClientException {
        super(BarbicanRsClientBuilder.factory().configuration(configuration).build());
        xProjectID = configuration.get("barbican.project.id");
        
        if(barbAuthToken == null)
            barbAuthToken = new BarbicanAuthToken(configuration);        
    }

}
