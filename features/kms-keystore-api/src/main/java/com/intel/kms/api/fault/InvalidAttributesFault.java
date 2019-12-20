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
public class InvalidAttributesFault extends Fault {
    private String type;
    private String message;

    public InvalidAttributesFault(String type, String message) {
        super(type);
        this.type = type;
	this.message = message;
    }

    public String getType() {
        return type;
    }

    public String getMessage() {
        return message;
    }
}
