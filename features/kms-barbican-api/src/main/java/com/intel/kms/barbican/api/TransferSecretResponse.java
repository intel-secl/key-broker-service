/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 *
 * @author jbuhacoff
 */
public class TransferSecretResponse {
    public byte[] secret;
    
    // the response is a byte array (application/octet-stream) not a json representation with base64
    @JsonValue
    public byte[] toByteArray() {
        return secret;
    }    
    
}
