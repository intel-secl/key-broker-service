/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.intel.kms.api.util.AbstractResponse;

public class DeleteKeyTransferPolicyResponse extends AbstractResponse {
	private String status;
	private String operation;
	private String keyId;

	public DeleteKeyTransferPolicyResponse() {
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

	protected void setKeyId(String keyId)
	{
		this.keyId = keyId;
	}

	public String getKeyId()
	{
		return this.keyId;
	}
}
