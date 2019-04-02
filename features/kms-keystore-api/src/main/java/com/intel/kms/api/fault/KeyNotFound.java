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
public class KeyNotFound extends Fault {
    private String keyId;

    public KeyNotFound(String keyId) {
        super(keyId);
        this.keyId = keyId;
    }

    public String getKeyId() {
        return keyId;
    }

}
