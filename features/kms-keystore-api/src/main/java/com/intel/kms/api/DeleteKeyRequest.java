/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * Delete request is used by clients to delete an existing key.
 * 
 * @author jbuhacoff
 */
public class DeleteKeyRequest {
    
    private String keyId;

    protected DeleteKeyRequest() {
    }

    public DeleteKeyRequest(String keyId) {
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }
    
    
}
