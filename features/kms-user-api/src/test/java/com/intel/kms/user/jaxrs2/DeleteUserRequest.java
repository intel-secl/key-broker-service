/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs2;

/**
 * Delete request is used by clients to delete an existing user.
 * 
 * @author jbuhacoff
 */
public class DeleteUserRequest {
    
    private String userId;

    protected DeleteUserRequest() {
    }

    public DeleteUserRequest(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }
    
    
}
