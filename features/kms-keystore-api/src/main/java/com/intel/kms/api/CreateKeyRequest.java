/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * To request the key server to create a new key, the key request
 * is essentially the set of key attributes that the new key should
 * have. 
 * 
 * The username indicates the user that is requesting the key to be
 * created. If the key transfer policy allows authorization (owner)
 * the newly created key will be automatically wrapped with the 
 * user's registered transfer public key and included in the response.
 * 
 * @author jbuhacoff
 */
public class CreateKeyRequest extends KeyAttributes {

    public CreateKeyRequest() {
        super();
    }
    
}
