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
