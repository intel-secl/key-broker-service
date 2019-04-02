/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.cipher.faults;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author jbuhacoff
 */
public class Algorithm extends Fault {
    private String algorithm;
    
    public Algorithm() {
        super("Algorithm");
    }
    public Algorithm(String algorithm) {
        super("Algorithm: %s", algorithm);
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }
    
}
