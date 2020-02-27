/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.api.fault;

import com.intel.dcsg.cpg.validation.Fault;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author rbhat
 */
@JsonIgnoreProperties({"description"})
public class NotFoundFault extends Fault {
    private String type;
    private String keyId;

    public NotFoundFault(String type, String keyId) {
        super(type);
        this.type = type;
        this.keyId = keyId;
    }

    public String getType() {
        return type;
    }

    @JsonProperty("id")
    public String getKeyId() {
        return keyId;
    }
}
