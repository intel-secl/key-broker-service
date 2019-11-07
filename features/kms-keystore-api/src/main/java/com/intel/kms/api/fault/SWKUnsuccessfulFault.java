/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author skamal 
 */
public class SWKUnsuccessfulFault extends Fault {
    private String swkKey;

    public SWKUnsuccessfulFault(String swkKey) {
        super(swkKey);
        this.swkKey = swkKey;
    }

    public String getChallenge() {
        return swkKey;
    }
    
    
}
