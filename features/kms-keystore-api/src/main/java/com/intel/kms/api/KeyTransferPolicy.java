/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class KeyTransferPolicy {
    @PathParam("keyId")
    public String keyId;
    
    /**
     * An expression 
     */
    public String tags;
}
