/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.usage.policy;

import com.intel.kms.api.util.AbstractResponse;

public class DeleteKeyUsagePolicyResponse extends AbstractResponse {
    private String status;
    private String operation;

    public DeleteKeyUsagePolicyResponse() {
        super();
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
}
