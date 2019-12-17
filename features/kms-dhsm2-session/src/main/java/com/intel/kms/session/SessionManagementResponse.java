/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.dhsm2.sessionManagement;

import com.intel.kms.api.util.AbstractResponse;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class SessionManagementResponse extends AbstractResponse {
    final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SessionManagementResponse.class);
    private String status;
    private String operation;
    private String SWKKey;
    private SessionManagementAttributes data;

    public SessionManagementResponse() {
        super();
    }

    public SessionManagementResponse(SessionManagementAttributes created) {
        super();
	this.data = created;
    }
    
    void setStatus(String status)
    {
	this.status = status;
    }

    public String getStatus()
    {
	return this.status;
    }

    public void setOperation(String operation)
    {
	this.operation = operation;
    }

    public String getOperation()
    {
	return this.operation;
    }

    public final SessionManagementAttributes getData() { return data; }
}
