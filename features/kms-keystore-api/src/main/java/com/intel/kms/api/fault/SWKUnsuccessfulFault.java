/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
