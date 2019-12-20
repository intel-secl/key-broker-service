/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.transfer.policy;

import com.intel.kms.api.util.AbstractResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

public class ReadKeyTransferPolicyResponse extends AbstractResponse {
	private String status;
	private String operation;
	private String keyId;

	public ReadKeyTransferPolicyResponse() {
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

	@JsonProperty("id")
		public String getKeyId()
		{
			return this.keyId;
		}

	private final ArrayList<KeyTransferPolicyAttributes> data = new ArrayList<>();

	@JsonInclude(JsonInclude.Include.NON_DEFAULT)
	@JsonProperty("created")
		public final List<KeyTransferPolicyAttributes> getData() { return data; }
}
