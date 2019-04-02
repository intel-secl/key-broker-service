/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * Get key attributes request is used by clients to retrieve metadata for an existing key.
 * 
 * @author jbuhacoff
 */
public class GetKeyAttributesRequest {
    
    private String keyId;

    public GetKeyAttributesRequest() {
        this.keyId = null;
    }

    public GetKeyAttributesRequest(String keyId) {
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
    
    
}
