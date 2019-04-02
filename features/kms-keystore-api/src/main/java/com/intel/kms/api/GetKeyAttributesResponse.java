/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.kms.api.util.AbstractResponse;

/**
 * If get key attributes is successful, the response will contain the key attributes
 * for the key specified in the request.
 * 
 * @author jbuhacoff
 */
public class GetKeyAttributesResponse extends AbstractResponse {
    private KeyAttributes data;

    public KeyAttributes getData() {
        return data;
    }

    public void setData(KeyAttributes data) {
        this.data = data;
    }
    
    
    
}
