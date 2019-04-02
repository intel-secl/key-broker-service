/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author jbuhacoff
 */
public class UnsupportedAlgorithm extends Fault {
    private String algorithm;

    public UnsupportedAlgorithm(String algorithm) {
        super(algorithm);
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }
    
    
}
