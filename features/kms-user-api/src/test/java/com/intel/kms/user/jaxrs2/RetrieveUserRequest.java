/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

/**
 * Delete request is used by clients to delete an existing user.
 * 
 * @author jbuhacoff
 */
public class RetrieveUserRequest {
    
    private String userId;

    protected RetrieveUserRequest() {
    }

    public RetrieveUserRequest(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }
    
    
}
