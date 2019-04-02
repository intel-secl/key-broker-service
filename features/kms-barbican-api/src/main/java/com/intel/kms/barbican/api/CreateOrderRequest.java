/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import javax.ws.rs.HeaderParam;

/**
 * Represents request to {@code POST /v1/orders}
 * 
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateOrderRequest {
    @JsonIgnore(true)
    @HeaderParam("X-Project-Id")
    public String projectId; // from header X-Project-Id: {project_id}

    public String type; // the literal "key" to identify the object type
    public RegisterSecretRequest meta;
}
