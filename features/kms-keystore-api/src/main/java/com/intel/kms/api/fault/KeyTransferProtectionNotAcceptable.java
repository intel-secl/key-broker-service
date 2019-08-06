/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;

/**
 *
 * @author jbuhacoff
 */
public class KeyTransferProtectionNotAcceptable extends Fault {
    private String algorithm;
    private Integer keyLength;

    public KeyTransferProtectionNotAcceptable(String algorithm, Integer keyLength) {
        super(String.format("%s-%s", algorithm, keyLength));
        this.algorithm = algorithm;
        this.keyLength = keyLength;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }
    
    

}
