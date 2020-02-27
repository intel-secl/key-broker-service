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
public class RemoteAttestationFault extends Fault {
    private String remoteAttestationChallenge;

    public RemoteAttestationFault(String remoteAttestationChallenge) {
        super(remoteAttestationChallenge);
        this.remoteAttestationChallenge = remoteAttestationChallenge;
    }

    public String getChallenge() {
        return remoteAttestationChallenge;
    }
    
    
}
