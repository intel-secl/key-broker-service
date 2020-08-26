/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.key.transfer;

import com.intel.kms.api.util.AbstractResponse;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The CreateKeyTransferResponse contains either key Transfer attributes
 * or any faults that prevented the application key transfer.
 *
 * @author rbhat
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class KeyTransferResponse extends AbstractResponse {

    private String status;
    private String operation;
    private KeyTransferAttributes data;

    public KeyTransferResponse() {
        super();
    }

    public KeyTransferResponse(KeyTransferAttributes created) {
        super();
	this.data = created;
    }

    protected void setStatus(String status)
    {
	this.status = status;
    }

    public String getStatus()
    {
	return this.status;
    }

    protected void setOperation(String operation)
    {
	this.operation = operation;
    }

    public String getOperation()
    {
	return this.operation;
    }

    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public final KeyTransferAttributes getData() { 
	return data;
    }
}
