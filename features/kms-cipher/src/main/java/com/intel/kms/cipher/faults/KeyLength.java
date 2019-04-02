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
public class KeyLength extends Fault {
    private Integer keyLength;
    
    public KeyLength() {
        super("Key length");
    }

    public KeyLength(Integer keyLength) {
        super("Key length: %d", keyLength);
        this.keyLength = keyLength;
    }

    public Integer getKeyLength() {
        return keyLength;
    }
}
