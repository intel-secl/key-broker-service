/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;

/**
 *
 * @author jbuhacoff
 */
public class GetOrderRequest {
    @PathParam("id")
    public String id; // from URL path template /v1/orders/{id}
    @HeaderParam("X-Project-Id")
    public String projectId; // from header X-Project-Id: {project_id}
}
