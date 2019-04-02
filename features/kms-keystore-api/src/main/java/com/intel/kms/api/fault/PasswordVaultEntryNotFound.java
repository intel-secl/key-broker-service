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
public class PasswordVaultEntryNotFound extends Fault {
    private String id;

    public PasswordVaultEntryNotFound(String id) {
        super(id);
        this.id = id;
    }

    public String getId() {
        return id;
    }
    
    
}
