/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Attributes;

/**
 * Transfer request is used by clients to retrieve a key.
 * 
 * In the future, additional fields may be added to allow the client to
 * specify the encryption and integrity algorithms it would prefer the
 * server use for protecting the key in transit - and the server will need
 * to choose among these a combination that the server supports and
 * satisfies the server's policy of protecting a key only with equivalent
 * or stronger cryptography.  Also the username and maybe permissions of the 
 * client will be
 * added so the manager can check if the user owns the requested key
 * to determine eligibility for "authorized user" transfer.
 * 
 * @author jbuhacoff
 */
public class TransferKeyRequest extends Attributes {
    
    private String keyId;
    private String username;

    public TransferKeyRequest() {
        this.keyId = null;
    }
    public TransferKeyRequest(String keyId) {
        this.keyId = keyId;
    }


    
    /**
     * Key ID to transfer
     * @return the requested key id
     */
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Username of the authorized user requesting the key.
     * This will be null when processing a trust-based key transfer request.
     * When present, the user must be authorized to receive the key
     * in accordance with the key transfer policy and, also dependent on
     * the policy, may be required to have a registered public key for wrapping.
     * @return 
     */
    public String getUsername() {
        return username;
    }


    
}
