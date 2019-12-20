/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 *
 * @author rbhat
 */
@JsonIgnoreProperties({"description"})
public class NotAuthorizedFault extends Fault {
    private String type;

    public NotAuthorizedFault(String type) {
        super(type);
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
