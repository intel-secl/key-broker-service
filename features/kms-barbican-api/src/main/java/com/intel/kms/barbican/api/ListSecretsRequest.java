/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.barbican.api;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.QueryParam;

/**
 * https://github.com/cloudkeep/barbican/wiki/Application-Programming-Interface
 * 
 * @author jbuhacoff
 */
public class ListSecretsRequest {
    @QueryParam("limit")
    public Integer limit;
    @QueryParam("offset")
    public Integer offset;
    @HeaderParam("X-Project-Id")
    public String projectId;
}
