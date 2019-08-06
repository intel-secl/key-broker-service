/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
