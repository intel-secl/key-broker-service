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
public class KeyTransferProtectionAlgorithmNotAcceptable extends Fault {
    private String algorithm;

    public KeyTransferProtectionAlgorithmNotAcceptable(String algorithm) {
        super(algorithm);
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

}
