/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.dhsm2.usage.policy;

import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.io.Copyable;
import com.intel.dcsg.cpg.iso8601.Iso8601Date;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author rbhat
 */

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class KeyUsagePolicyAttributes extends Attributes implements Copyable {

    private String keyUsagePolicyId;
    private String notAfter;
    private String notBefore;
    private int leaseTimeLimit;

    @JsonFormat(shape=JsonFormat.Shape.STRING, pattern="yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private Iso8601Date createdAt;

    protected void setKeyUsagePolicyId(String keyUsagePolicyId)
    {
	this.keyUsagePolicyId = keyUsagePolicyId;
    }

    @JsonProperty("id")
    public String getKeyUsagePolicyId()
    {
	return this.keyUsagePolicyId;
    }

    public String getNotAfter()
    {
	return this.notAfter;
    }

    protected void setNotAfter(String notAfter)
    {
	this.notAfter = notAfter;
    }

    public String getNotBefore()
    {
	return this.notBefore;
    }

    protected void setNotBefore(String notBefore)
    {
	this.notBefore = notBefore;
    }
 
    public int getLeaseTimeLimit()
    {
	return this.leaseTimeLimit;
    }

    protected void setLeaseTimeLimit(int leaseTimeLimit)
    {
	this.leaseTimeLimit = leaseTimeLimit;
    }

    protected void setCreatedAt(Iso8601Date createdAt)
    {
	this.createdAt = createdAt;
    }

    public Iso8601Date getCreatedAt()
    {
	return this.createdAt;
    }

    public void copyFrom(KeyUsagePolicyAttributes source) {
        super.copyFrom(source);
        this.setKeyUsagePolicyId(source.getKeyUsagePolicyId());
        this.setNotAfter(source.getNotAfter());
        this.setNotBefore(source.getNotBefore());
        this.setLeaseTimeLimit(source.getLeaseTimeLimit());
        this.setCreatedAt(source.getCreatedAt());
    }
}
