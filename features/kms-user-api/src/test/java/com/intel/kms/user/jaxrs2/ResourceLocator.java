/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.user.jaxrs2;

import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class ResourceLocator {
    @PathParam("id")
    private String id;

    public ResourceLocator() {
    }

    public ResourceLocator(String id) {
        this.id = id;
    }

    
    
    public String getId() {
        return id;
    }
    
    
    
}
